/* stack_snapshot.bpf.h
 *
 * BPF-side helpers for the shared stack snapshot. Include this *after* defining
 * the ringbuf the engine uses:
 *
 *   #define ARES_SNAPSHOT_RB events         // syscalls: their ringbuf name
 *   #define ARES_SNAPSHOT_RB events_rb      // funcs: their ringbuf name
 *   #include "common/stack_snapshot.bpf.h"
 *
 * The engine also needs its own `stack_seen` BPF_MAP_TYPE_HASH map and a
 * `bump_dropped()` (from common/bpf_drop.bpf.h) in scope.
 *
 * Requires: vmlinux.h, bpf_helpers.h, bpf_tracing.h, bpf_core_read.h,
 *           common/stack_snapshot.h (included below), common/bpf_drop.bpf.h.
 *
 * Also pulls in common/coverage.bpf.h (CR5) for cov_bump()/coverage_stats,
 * used below to count truncated snapshots. Include-guarded, so it's safe even
 * if the including engine TU also includes it directly.
 */
#ifndef ARES_STACK_SNAPSHOT_BPF_H
#define ARES_STACK_SNAPSHOT_BPF_H

#include "common/stack_snapshot.h"
#include "common/coverage.bpf.h"

/* FNV-1a over the captured return addresses, seeded with the tgid so the same
 * call path in different processes gets distinct ids and one process's snapshot
 * never suppresses another's. Never returns 0 (0 = "no stack id").
 *
 * `cap` is the caller's array capacity and MUST be a compile-time constant equal
 * to the real length of `stack[]` (syscalls: SYSC_MAX_STACK_DEPTH=32, funcs:
 * STACK_DEPTH=16). The loop is fully unrolled, so the verifier proves exactly
 * `cap` in-bounds reads; the runtime `if (i < n)` guard alone can't bound them
 * (n is not known at load time). Passing a `cap` larger than the array reads out
 * of bounds and the program fails to load. */
static __always_inline __u64 ares_hash_stack(__u64 *stack, int n, __u32 tgid, int cap)
{
	__u64 h = 0xcbf29ce484222325ULL ^ ((__u64)tgid << 32);
	#pragma clang loop unroll(full)
	for (int i = 0; i < cap; i++) {
		if (i < n) {
			h ^= stack[i];
			h *= 0x100000001b3ULL;
		}
	}
	return h ? h : 1;
}

/* Emit one stack-snapshot record: full GP register file + a bounded copy of the
 * user stack from sp upward. Two fixed-size attempts so a fault near the top of
 * the stack still yields the smaller window. ev_type is the engine's discriminator
 * value for a stack record (e.g. SYSC_EV_STACK or ARES_EVENT_STACK). */
static __always_inline void ares_emit_stack_snapshot(struct pt_regs *user_regs,
						     __u32 tgid, __u32 tid,
						     __u64 sid, __u32 ev_type)
{
	struct ares_stack_snapshot *s =
		bpf_ringbuf_reserve(&ARES_SNAPSHOT_RB, sizeof(*s), 0);
	if (!s) {
		bump_dropped();
		return;
	}
	s->h.type = ev_type;
	s->h.pid  = tgid;
	s->h.tid  = tid;
	s->h._pad = 0;
	s->stack_id = sid;
	s->pc = BPF_CORE_READ(user_regs, pc);
	s->sp = BPF_CORE_READ(user_regs, sp);
	s->fp = BPF_CORE_READ(user_regs, regs[29]);
	s->lr = BPF_CORE_READ(user_regs, regs[30]);
	#pragma clang loop unroll(full)
	for (int i = 0; i < ARES_SNAP_NREG; i++)
		s->regs[i] = BPF_CORE_READ(user_regs, regs[i]);
	/* Target userspace TLS base (TPIDR_EL0). Not in pt_regs; read the running
	 * task's saved thread pointer. ART's Thread* lives at
	 * *(tls_base + TLS_SLOT_ART_THREAD_SELF*8). Kernel read only — firewall-safe. */
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	s->tls_base = BPF_CORE_READ(t, thread.uw.tp_value);
	s->_pad[0] = 0; s->_pad[1] = 0; s->_pad[2] = 0;
	s->snap_len = 0;
	/* Fault-tolerant chunked capture (W3-window). Read the stack from sp in
	 * ARES_SNAP_CHUNK pieces; on the first faulting (unmapped) chunk, latch
	 * `stop` so later chunks are skipped — never skip a hole and continue
	 * (the unwinder requires snap[k] == *(sp+k)). No `break`: a data-dependent
	 * break can defeat unroll(full); the stop-flag form unrolls to straight-line
	 * conditionals matching this file's proven idiom. */
	int stop = 0;
	#pragma clang loop unroll(full)
	for (int i = 0; i < ARES_SNAP_MAX / ARES_SNAP_CHUNK; i++) {
		if (!stop && s->sp &&
		    bpf_probe_read_user(s->snap + i * ARES_SNAP_CHUNK,
					ARES_SNAP_CHUNK,
					(const __u8 *)s->sp + i * ARES_SNAP_CHUNK) == 0)
			s->snap_len = (i + 1) * ARES_SNAP_CHUNK;
		else
			stop = 1;
	}
	/* truncated = "window-capped, stack may extend beyond capture" (genuinely
	 * incomplete). A fault stop gives snap_len < MAX = reached stack_base =
	 * captured all mapped stack = complete (truncated 0). */
	s->truncated = (s->snap_len == ARES_SNAP_MAX);
	if (s->truncated)
		cov_bump(COV_TRUNC);
	bpf_ringbuf_submit(s, 0);
}

#endif /* ARES_STACK_SNAPSHOT_BPF_H */
