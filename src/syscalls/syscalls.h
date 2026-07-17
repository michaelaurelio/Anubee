/* syscalls.h
 *
 * Layout shared byte-for-byte between the BPF program (syscalls.bpf.c) and the
 * userspace loader (syscalls.c). The BPF side gets the fixed-width types from
 * vmlinux.h; the userspace side must include <linux/types.h> before this header.
 */
#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "common/trace_schema.h"
#include "common/stack_snapshot.h"  /* struct anubee_stack_snapshot + ANUBEE_SNAP_* */

#define SYSC_MAX_STACK_DEPTH 32
#define SYSC_MAX_RANGES      8
#define SYSC_SYSCALL_NARGS   6

/* SYSC_SNAP_MAX/SMALL kept as aliases for any downstream code that used the old
 * names; the canonical constants are now ANUBEE_SNAP_MAX/SMALL in stack_snapshot.h. */
#define SYSC_SNAP_MAX   ANUBEE_SNAP_MAX
#define SYSC_SNAP_SMALL ANUBEE_SNAP_SMALL

/* Inline capture of string (const char *) arguments. We resolve at most the
 * first SYSC_STR_SLOTS args (covers every path-taking syscall), each up to
 * SYSC_STR_MAX bytes, read from the caller's memory at syscall entry. */
#define SYSC_STR_SLOTS       4
#define SYSC_STR_MAX         256

/* Raw sockaddr captured at entry for connect/bind/sendto (family + port + addr,
 * or a unix path prefix), decoded to ip:port in userspace. */
#define SYSC_SOCK_MAX        64

enum syscalls_event_type {
	SYSC_EV_SYSCALL = 1,
	SYSC_EV_MAP     = 2,
	SYSC_EV_UNMAP   = 3,
	SYSC_EV_RETURN  = 4,
	SYSC_EV_STACK   = 5,        /* one stack snapshot (first sight of a stack) */
};

/* Entry-only syscall record: number + raw args + resolved string args + stack. */
struct syscalls_syscall_event {
	struct trace_event_header h;
	__u64 nr;
	__u64 ktime;                                  /* boot-monotonic ns at syscall entry
							 * (bpf_ktime_get_ns) - the cross-engine
							 * chronological join key (EPIC C3) */
	__u64 args[SYSC_SYSCALL_NARGS];
	__s32 stack_sz;                              /* bytes valid in stack[] */
	__u32 str_present;                           /* bit i set => str[i] is valid */
	__u64 stack_id;                              /* signature of stack[]; 0 = none. Links
						      * to a SYSC_EV_STACK snapshot record. */
	__u64 stack[SYSC_MAX_STACK_DEPTH];       /* user return addresses */
	char  str[SYSC_STR_SLOTS][SYSC_STR_MAX]; /* string value of args[i] */
	__u32 sock_len;                              /* bytes valid in sock[], 0 = none */
	__u8  sock[SYSC_SOCK_MAX];               /* raw sockaddr (connect/bind/sendto) */
	__u8  compat;      /* 1 = 32-bit/AArch32 (do_el0_svc_compat), a distinct
			    * EABI syscall-number namespace: str[]/sock[] are
			    * always empty here since arg_types/sock_args are
			    * keyed on arm64 numbers (CR2). */
};

/* One stack snapshot — now the shared struct anubee_stack_snapshot from
 * common/stack_snapshot.h. Alias kept so old callers in this engine still compile. */
typedef struct anubee_stack_snapshot syscalls_stack_snapshot;

/* Executable file-backed mappings (uprobe_mmap) and unmaps (uprobe_munmap) are
 * captured by the shared probe in common/lib_trace.bpf.h and arrive as
 * struct lib_map_event / struct lib_unmap_event (see common/lib_trace.h). */

/* Return value of a previously-emitted syscall, paired by tid (from the
 * kretprobe.multi on __arm64_sys_*). */
struct syscalls_return_event {
	struct trace_event_header h;
	__s64 retval;
};

/* Per-process set of executable ranges belonging to the target library, kept in
 * a BPF map so the syscall hook can test stack origin in-kernel. Filled by the
 * loader the moment it sees the library mapped. */
struct syscalls_lib_ranges {
	__u32 count;
	__u32 _pad;
	struct {
		__u64 start;
		__u64 end;
	} r[SYSC_MAX_RANGES];
};

/* ---- userspace engine driver (hidden from the BPF compile) ---------------
 * The kprobe engine is split into three phases so it can run standalone
 * (cmd_syscalls) or be driven by the `trace` coordinator alongside the uprobe
 * engine. __VMLINUX_H__ is defined by vmlinux.h, which the BPF side includes
 * first, so this stays out of the BPF compile. */
#ifndef __VMLINUX_H__
#include "common/engine_driver.h"  // syscalls_setup/_run/_teardown (AA3)
#endif

#endif /* SYSCALLS_H */
