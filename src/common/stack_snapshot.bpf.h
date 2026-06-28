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
 */
#ifndef ARES_STACK_SNAPSHOT_BPF_H
#define ARES_STACK_SNAPSHOT_BPF_H

#include "common/stack_snapshot.h"

/* Maximum stack depth the hash function iterates over. Both engines fit:
 * syscalls uses SYSC_MAX_STACK_DEPTH=32, funcs uses STACK_DEPTH=16. */
#define ARES_HASH_MAX_DEPTH 32

/* FNV-1a over the captured return addresses, seeded with the tgid so the same
 * call path in different processes gets distinct ids and one process's snapshot
 * never suppresses another's. Never returns 0 (0 = "no stack id"). */
static __always_inline __u64 ares_hash_stack(__u64 *stack, int n, __u32 tgid)
{
	__u64 h = 0xcbf29ce484222325ULL ^ ((__u64)tgid << 32);
	#pragma clang loop unroll(full)
	for (int i = 0; i < ARES_HASH_MAX_DEPTH; i++) {
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
	s->truncated = 0;
	s->_pad[0] = 0; s->_pad[1] = 0; s->_pad[2] = 0;
	s->snap_len = 0;
	const void *sp = (const void *)s->sp;
	if (s->sp && bpf_probe_read_user(s->snap, ARES_SNAP_MAX, sp) == 0)
		s->snap_len = ARES_SNAP_MAX;
	else if (s->sp && bpf_probe_read_user(s->snap, ARES_SNAP_MID, sp) == 0) {
		s->snap_len = ARES_SNAP_MID;
		s->truncated = 1;
	} else if (s->sp && bpf_probe_read_user(s->snap, ARES_SNAP_SMALL, sp) == 0) {
		s->snap_len = ARES_SNAP_SMALL;
		s->truncated = 1;
	}
	bpf_ringbuf_submit(s, 0);
}

#endif /* ARES_STACK_SNAPSHOT_BPF_H */
