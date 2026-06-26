#ifndef ARES_UNWIND_REGS_H
#define ARES_UNWIND_REGS_H

#include "syscalls/syscalls.h"

/* Frozen aarch64 GP register state used as the initial frame for CFI unwinding. */
struct ares_unwind_regs {
	__u64 x[31];   /* x0..x30 */
	__u64 sp;
	__u64 pc;
};

static inline void unwind_regs_from_snapshot(const struct syscalls_stack_snapshot *s,
					     struct ares_unwind_regs *out)
{
	for (int i = 0; i < 31; i++)
		out->x[i] = s->regs[i];
	out->sp = s->sp;
	out->pc = s->pc;
}

#endif /* ARES_UNWIND_REGS_H */
