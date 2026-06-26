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

/* Full window; SNAP_SMALL is the fallback when SNAP_MAX faults near the top of
 * the stack region (both are power-of-two so bpf_probe_read_user is happy). */
#define ARES_SNAP_MAX   8192
#define ARES_SNAP_SMALL 2048
#define ARES_SNAP_NREG  31   /* x0..x30 */

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
	__u8  truncated;                  /* 1 = snap[] smaller than stack used */
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
