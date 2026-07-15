// SPDX-License-Identifier: GPL-2.0
// See drain_progress.h. This file owns only the impure half: the clock, the
// tty check, the poll loop and the rendering. All arithmetic and formatting is
// static inline in the header so it can be unit-tested without any of this.
#include "common/drain_progress.h"

#include "common/human_out.h"
#include "common/runtime.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Poll the queue this often. Independent of the redraw cadence: we must notice
// used==0 promptly to keep teardown snappy, but redrawing that fast would just
// flicker.
#define TICK_NS    (100ULL * 1000000ULL)
#define TTY_REDRAW_NS   (250ULL * 1000000ULL)   // 4/s, in place
#define NOTTY_LINE_NS  (2000ULL * 1000000ULL)   // one line per 2s, no \r

static unsigned long long ts_to_ns(const struct timespec *ts)
{
    return (unsigned long long)ts->tv_sec * 1000000000ULL
         + (unsigned long long)ts->tv_nsec;
}

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts_to_ns(&ts);
}

void ares_drain_progress_begin(struct ares_drain_progress *d,
                               struct ares_evq *q, const char *label)
{
    memset(d, 0, sizeof *d);
    d->q     = q;
    d->label = label;

    // Freeze the denominator. Safe because by teardown the ring poll loop has
    // already exited, so nothing can push again and q->used only falls.
    pthread_mutex_lock(&q->m);
    d->total_bytes = q->used;
    d->popped0     = q->popped;
    d->total_recs  = q->pushed - q->popped;
    pthread_mutex_unlock(&q->m);

    clock_gettime(CLOCK_MONOTONIC, &d->t0);
    d->last_render = d->t0;
    d->tty   = isatty(STDERR_FILENO);
    d->shown = 0;

    // Independent of the 300ms UI timer on purpose: a fast double-tap must
    // still get the warning even when the bar never had time to appear.
    ares_drain_set_active(1);
}

// The header names the BACKLOG, not the run total. A user who traced 200k
// events must not read "8,192" as "where did my other records go" - they are
// already written and safe; this is only what the worker had not caught up on.
static void render_header(struct ares_drain_progress *d)
{
    char tbuf[32];
    drain_fmt_count(d->total_recs, tbuf, sizeof tbuf);
    err_print("[drain:%s] finishing %s queued events "
              "(already-written records are safe) - do not interrupt\n",
              d->label, tbuf);
    d->shown = 1;
}

static void render(struct ares_drain_progress *d, size_t used,
                   unsigned long long popped, unsigned long long elapsed_ns)
{
    char nbuf[32], tbuf[32], dbuf[24];
    int  pct = drain_pct(d->total_bytes, used);

    drain_fmt_count(popped - d->popped0, nbuf, sizeof nbuf);
    drain_fmt_count(d->total_recs, tbuf, sizeof tbuf);

    if (!d->shown)
        render_header(d);

    if (!d->tty) {
        // No \r, no ANSI: a redirected stderr stays a readable log.
        err_print("[drain:%s] %d%% (%s/%s)\n", d->label, pct, nbuf, tbuf);
        return;
    }

    // pct is bytes-based while (nbuf/tbuf) is record-based, so the two
    // deliberately advance at different rates - see drain_pct's comment. Not a
    // bug: the drain can be 47% through the work and 38% through the records.
    char bar[ARES_DRAIN_BAR_CELLS * 4 + 1];
    int  filled = pct * ARES_DRAIN_BAR_CELLS / 100;
    int  bi = 0;
    for (int i = 0; i < ARES_DRAIN_BAR_CELLS; i++) {
        const char *cell = (i < filled) ? "█" : "░";
        bi += snprintf(bar + bi, sizeof bar - (size_t)bi, "%s", cell);
    }

    char line[256];
    long eta = drain_eta_secs(d->total_bytes, used, elapsed_ns);
    if (eta >= 0) {
        drain_fmt_duration(eta, dbuf, sizeof dbuf);
        snprintf(line, sizeof line, "[drain:%s] %s  %d%%  (%s/%s)  ~%s left",
                 d->label, bar, pct, nbuf, tbuf, dbuf);
    } else {
        snprintf(line, sizeof line, "[drain:%s] %s  %d%%  (%s/%s)",
                 d->label, bar, pct, nbuf, tbuf);
    }
    human_progress_set(line);
}

void ares_drain_progress_join(struct ares_drain_progress *d, pthread_t worker)
{
    for (;;) {
        pthread_mutex_lock(&d->q->m);
        size_t used = d->q->used;
        unsigned long long popped = d->q->popped;
        pthread_mutex_unlock(&d->q->m);

        // ares_evq_pop returns 0 exactly when used==0 && done, and done was set
        // before this loop started - so an empty queue means the worker is
        // already on its way out. The join below then blocks for at most the
        // last record's processing.
        if (used == 0)
            break;

        unsigned long long now     = now_ns();
        unsigned long long elapsed = now - ts_to_ns(&d->t0);
        if (drain_should_show(elapsed, d->total_bytes)) {
            unsigned long long since = now - ts_to_ns(&d->last_render);
            unsigned long long every = d->tty ? TTY_REDRAW_NS : NOTTY_LINE_NS;
            if (!d->shown || since >= every) {
                render(d, used, popped, elapsed);
                clock_gettime(CLOCK_MONOTONIC, &d->last_render);
            }
        }

        struct timespec ts = { 0, (long)TICK_NS };
        nanosleep(&ts, NULL);   // wakes early on a signal; harmless
    }

    pthread_join(worker, NULL);

    if (d->shown) {
        char tbuf[32], dbuf[24];
        unsigned long long elapsed = now_ns() - ts_to_ns(&d->t0);
        human_progress_set(NULL);          // retire the bar before the last line
        drain_fmt_count(d->total_recs, tbuf, sizeof tbuf);
        drain_fmt_duration((long)(elapsed / 1000000000ULL), dbuf, sizeof dbuf);
        err_print("[drain:%s] done: %s events in %s\n", d->label, tbuf, dbuf);
    }
    ares_drain_set_active(0);
}
