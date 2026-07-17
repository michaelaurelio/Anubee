// SPDX-License-Identifier: GPL-2.0
// Progress reporting for the post-Ctrl-C queue drain.
//
// On Ctrl-C the poll loop exits but the worker keeps draining the queue, and
// under --snapshot every queued snapshot costs a full CFI unwind - so the drain
// can run for minutes with no output at all. A user who reads that as a hang
// hits Ctrl-C again, which _exit(130)s and throws away every still-queued
// record. This makes the drain legible so that never looks like the right move.
//
// The math below is pure and lives here as static inline (no .c, no queue, no
// terminal needed) so it is host-testable - same rationale as snapshot_gate.h.
#ifndef __ANUBEE_COMMON_DRAIN_PROGRESS_H
#define __ANUBEE_COMMON_DRAIN_PROGRESS_H

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "common/evqueue.h"

// Stay silent until the drain has already run this long. Time-triggered rather
// than size-triggered: self-calibrating across devices, and it fires exactly
// when a human starts wondering if it hung. A fast drain prints nothing, so the
// "do not interrupt" line keeps its meaning.
#define ANUBEE_DRAIN_SHOW_AFTER_NS  (300ULL * 1000000ULL)
// Suppress the ETA until there is enough elapsed time for the rate to mean
// something.
#define ANUBEE_DRAIN_ETA_AFTER_NS   (1000ULL * 1000000ULL)
#define ANUBEE_DRAIN_BAR_CELLS      16

// Show the UI at all? Zero backlog also guards drain_pct's divisor.
static inline int drain_should_show(unsigned long long elapsed_ns,
                                    size_t total_bytes)
{
    return total_bytes > 0 && elapsed_ns >= ANUBEE_DRAIN_SHOW_AFTER_NS;
}

// Percent of the frozen backlog drained, from BYTES. Bytes rather than records
// because the expensive records are also the big ones (32KB snapshot + CFI
// unwind vs ~150B syscall record), so bytes track real work and give a
// trustworthy ETA where a record count would stall at 90%.
// No producer exists during a drain, so used > total_bytes is unreachable - the
// clamp is here so a future refactor that breaks that invariant degrades into a
// wrong number instead of an integer underflow.
static inline int drain_pct(size_t total_bytes, size_t used)
{
    if (total_bytes == 0)
        return 100;
    if (used > total_bytes)
        used = total_bytes;
    unsigned long long done = (unsigned long long)(total_bytes - used);
    unsigned long long p = done * 100ULL / (unsigned long long)total_bytes;
    return p > 100 ? 100 : (int)p;
}

// Seconds left, or -1 to suppress. Running average (drained/elapsed) rather
// than an EMA: it self-smooths and has no tuning knob to get wrong.
static inline long drain_eta_secs(size_t total_bytes, size_t used,
                                  unsigned long long elapsed_ns)
{
    if (elapsed_ns < ANUBEE_DRAIN_ETA_AFTER_NS)
        return -1;
    if (used > total_bytes)
        return -1;
    if (used == 0)
        return 0;
    double done = (double)(total_bytes - used);
    if (done <= 0.0)
        return -1;                       // no rate yet
    double elapsed_s = (double)elapsed_ns / 1e9;
    double eta = (double)used * elapsed_s / done;
    if (eta < 0.0)
        return -1;
    if (eta > 359999.0)
        eta = 359999.0;                  // 99h59m59s ceiling
    return (long)(eta + 0.5);
}

// "200412" -> "200,412". Falls back to the bare number if out is too small.
static inline void drain_fmt_count(unsigned long long n, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    char tmp[24];
    int len = snprintf(tmp, sizeof tmp, "%llu", n);
    if (len < 1) { out[0] = '\0'; return; }
    int total = len + (len - 1) / 3;
    if ((size_t)total + 1 > cap) { snprintf(out, cap, "%llu", n); return; }
    out[total] = '\0';
    int oi = total - 1, ti = len - 1, run = 0;
    while (ti >= 0) {
        out[oi--] = tmp[ti--];
        if (++run % 3 == 0 && ti >= 0)
            out[oi--] = ',';
    }
}

// 72 -> "1m12s". Units omitted above the largest non-zero one.
static inline void drain_fmt_duration(long secs, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    if (secs < 0)
        secs = 0;
    long h = secs / 3600, m = (secs % 3600) / 60, s = secs % 60;
    if (h > 0)
        snprintf(out, cap, "%ldh%ldm%lds", h, m, s);
    else if (m > 0)
        snprintf(out, cap, "%ldm%lds", m, s);
    else
        snprintf(out, cap, "%lds", s);
}

// One drain's progress state. Totals are frozen at begin: by teardown the poll
// loop has already exited, so no producer exists and q->used can only fall -
// the denominator is exact, not an estimate. Holds under `trace` too, which
// joins every run-thread before any teardown and tears down sequentially.
struct anubee_drain_progress {
    struct anubee_evq *q;
    const char      *label;        // engine name; disambiguates under `trace`
    size_t           total_bytes;  // q->used, frozen at begin
    unsigned long long total_recs; // q->pushed - q->popped, frozen at begin
    unsigned long long popped0;    // q->popped, frozen at begin
    struct timespec  t0, last_render;
    int              tty;          // isatty(STDERR_FILENO)
    int              shown;        // header printed yet?
};

// Freeze the totals, start the clock, and mark a drain in flight (so a 2nd
// Ctrl-C warns). Call BEFORE setting q->done.
void anubee_drain_progress_begin(struct anubee_drain_progress *d,
                               struct anubee_evq *q, const char *label);

// Render until the queue is empty, then join. Replaces a bare pthread_join:
// anubee_evq_pop exits exactly when used==0 && done, so once used hits 0 the
// worker is already guaranteed to exit and the join blocks for at most one
// record's processing. Clears the drain-active mark on return.
void anubee_drain_progress_join(struct anubee_drain_progress *d, pthread_t worker);

#endif /* __ANUBEE_COMMON_DRAIN_PROGRESS_H */
