// SPDX-License-Identifier: GPL-2.0
// Pair a syscall's entry event with its return value, keyed by thread id.
//
// An analyzer's entry kprobe emits the full event; a kretprobe on the same
// syscall emits only the return value for that thread. A thread has at most
// one syscall in flight, so the analyzer holds each thread's entry event here
// until its result arrives, then emits the two together. Nothing is dropped:
// an entry whose result is lost (a newer entry on the same thread, a full
// table, teardown) is emitted with known=0.
#ifndef ANUBEE_SYSRET_PEND_H
#define ANUBEE_SYSRET_PEND_H

#include <stddef.h>
#include <stdint.h>

struct sysret_pend;

// A syscall's outcome as carried into a record: ret >= 0 success, -errno failure.
// known == 0: the result never arrived (lost, or the run ended first).
struct sys_result {
    long long ret;
    int known;
};

// ret is the syscall's return value (>= 0 success, -errno failure); valid only when known.
typedef void (*sysret_emit_fn)(void *ctx, const void *ev, size_t len, long long ret, int known);

struct sysret_pend *sysret_pend_new(unsigned cap, size_t max_ev);
void sysret_pend_free(struct sysret_pend *p);

// Hold a copy of ev until tid's result arrives. An entry already pending for
// tid is emitted first (known=0). If the table is full or ev is bigger than
// max_ev, ev is emitted right away (known=0).
void sysret_pend_entry(struct sysret_pend *p, uint32_t tid, const void *ev, size_t len,
                       sysret_emit_fn emit, void *ctx);

// Emit tid's pending entry with ret. Returns 1 if there was one, 0 otherwise.
int sysret_pend_result(struct sysret_pend *p, uint32_t tid, long long ret,
                       sysret_emit_fn emit, void *ctx);

// Emit every pending entry (known=0) and empty the table.
void sysret_pend_flush(struct sysret_pend *p, sysret_emit_fn emit, void *ctx);

unsigned sysret_pend_count(const struct sysret_pend *p);

// "ENOENT" for -2 etc.; NULL for success or an errno not in the table.
const char *sys_errno_name(long long ret);

#endif
