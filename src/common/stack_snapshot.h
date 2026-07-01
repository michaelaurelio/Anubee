/* stack_snapshot.h
 *
 * Shared layout for the register-file + bounded-user-stack snapshot used by
 * both the syscalls (kprobe) and funcs (uprobe) engines. The record is captured
 * in-kernel when the thread is trapped — user registers and the stack are frozen
 * — and consumed off-device by the DWARF CFI unwinder (src/common/cfi_unwind.*).
 *
 * Shared byte-for-byte between the BPF programs (which get fixed-width types
 * from vmlinux.h) and the userspace loaders (which must include <linux/types.h>
 * before this header).
 */
#ifndef ARES_STACK_SNAPSHOT_H
#define ARES_STACK_SNAPSHOT_H

#include "common/trace_schema.h"

/* User-stack capture window. SNAP_MAX is the full window; the unwinder needs it
 * large enough to reach deep frames' spill slots (a frame's saved-RA can sit well
 * above sp — e.g. a framework lib ~12 frames up past the JNI boundary), so the
 * cross-trampoline unwind would otherwise truncate mid-stack. SNAP_MID/SNAP_SMALL
 * are the fault fallbacks when the full read runs off the top of the mapped stack
 * region (3 tiers so a fault on the big read still yields a useful window). All
 * power-of-two so bpf_probe_read_user is happy. Records are deduped per distinct
 * stack, so the larger window costs ring bandwidth only on first sight of a stack. */
#define ARES_SNAP_MAX   32768
#define ARES_SNAP_MID   8192
#define ARES_SNAP_SMALL 2048
#define ARES_SNAP_NREG  31   /* x0..x30 */

/* Per-chunk granularity for fault-tolerant capture (W3-window): the stack is
 * read in ARES_SNAP_CHUNK-sized pieces, stopping at the first unmapped page, so
 * a fault near the top of the mapped stack still yields the full contiguous
 * prefix instead of dropping to a coarse 8 KB tier. 4096 = common Android page. */
#define ARES_SNAP_CHUNK 4096
_Static_assert(ARES_SNAP_MAX % ARES_SNAP_CHUNK == 0,
               "ARES_SNAP_MAX must be a whole number of chunks (loop drops the remainder)");

/* One stack snapshot: full GP register file + a bounded copy of the thread's
 * user stack from sp upward, captured at the point the thread trapped into the
 * kernel (kprobe/do_el0_svc for syscalls, BRK uprobe for funcs). Deduped by a
 * stack signature so the heavy snap[] rides the ring only on the first sight of
 * each distinct call stack. SNAP_MAX is the largest ring record per engine. */
struct ares_stack_snapshot {
	struct trace_event_header h;
	__u64 stack_id;
	__u64 pc, sp, fp, lr;            /* user pc / sp / x29 / x30 (legacy mirror) */
	__u64 regs[ARES_SNAP_NREG];      /* full GP file x0..x30 (CFI initial state) */
	__u32 snap_len;                   /* bytes valid in snap[] (from sp up) */
	__u8  truncated;                  /* 1 = snap_len==ARES_SNAP_MAX (window-capped, stack may extend beyond); 0 = a chunk faulted = reached stack_base = all mapped stack captured */
	__u8  _pad[3];
	__u8  snap[ARES_SNAP_MAX];        /* user stack bytes starting at sp */
};

/* ---- userspace helpers (hidden from the BPF compile) --------------------- */
#ifndef __VMLINUX_H__
#include <stddef.h>   /* size_t for jbuf */

struct jbuf;   /* forward-declare; full def in common/emit.h */

/* Serialise a snapshot to j as {"type":"stack",...}\n. Caller owns the file
 * write. Defined in common/stack_snapshot.c. */
void ares_stack_snapshot_emit_json(struct jbuf *j,
				   const struct ares_stack_snapshot *s);


/* Frozen aarch64 GP register state used as the initial frame for CFI unwinding.
 * Generalised from src/syscalls/unwind_regs.h (W3 fix: no longer engine-coupled). */
struct ares_unwind_regs {
	__u64 x[ARES_SNAP_NREG];  /* x0..x30 */
	__u64 sp;
	__u64 pc;
};

static inline void unwind_regs_from_snapshot(const struct ares_stack_snapshot *s,
					     struct ares_unwind_regs *out)
{
	for (int i = 0; i < ARES_SNAP_NREG; i++)
		out->x[i] = s->regs[i];
	out->sp = s->sp;
	out->pc = s->pc;
}

#endif /* __VMLINUX_H__ */
#endif /* ARES_STACK_SNAPSHOT_H */
