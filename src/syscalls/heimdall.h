/* heimdall.h
 *
 * Layout shared byte-for-byte between the BPF program (heimdall.bpf.c) and the
 * userspace loader (heimdall.c). The BPF side gets the fixed-width types from
 * vmlinux.h; the userspace side must include <linux/types.h> before this header.
 */
#ifndef HEIMDALL_H
#define HEIMDALL_H

#define HEIMDALL_MAX_STACK_DEPTH 32
#define HEIMDALL_MAX_RANGES      8
#define HEIMDALL_SYSCALL_NARGS   6
#define HEIMDALL_MAX_NAME        64

/* Stack snapshot (Phase 2a): registers + a bounded copy of the thread's user
 * stack, captured in eBPF at the syscall point (the thread is in-kernel, so the
 * user stack is frozen) for off-device DWARF unwinding. Deduplicated by a stack
 * signature so the heavy snap[] rides the ring only on the first sight of each
 * distinct stack. SNAP_MAX is the full window; SNAP_SMALL the fallback when the
 * full read faults (near the top of the stack region). */
#define HEIMDALL_SNAP_MAX        8192
#define HEIMDALL_SNAP_SMALL      2048

/* Inline capture of string (const char *) arguments. We resolve at most the
 * first HEIMDALL_STR_SLOTS args (covers every path-taking syscall), each up to
 * HEIMDALL_STR_MAX bytes, read from the caller's memory at syscall entry. */
#define HEIMDALL_STR_SLOTS       4
#define HEIMDALL_STR_MAX         256

/* Raw sockaddr captured at entry for connect/bind/sendto (family + port + addr,
 * or a unix path prefix), decoded to ip:port in userspace. */
#define HEIMDALL_SOCK_MAX        64

/* Linux VMA flag (not always macro-defined in vmlinux.h). */
#ifndef HEIMDALL_VM_EXEC
#define HEIMDALL_VM_EXEC 0x00000004UL
#endif

enum heimdall_event_type {
	HEIMDALL_EV_SYSCALL = 1,
	HEIMDALL_EV_MAP     = 2,
	HEIMDALL_EV_UNMAP   = 3,
	HEIMDALL_EV_RETURN  = 4,
	HEIMDALL_EV_STACK   = 5,        /* one stack snapshot (first sight of a stack) */
};

/* Common 16-byte header at the front of every ring-buffer record. `pid` is the
 * thread-group id (process), `tid` the thread. */
struct heimdall_hdr {
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 _pad;
};

/* Entry-only syscall record: number + raw args + resolved string args + stack. */
struct heimdall_syscall_event {
	struct heimdall_hdr h;
	__u64 nr;
	__u64 args[HEIMDALL_SYSCALL_NARGS];
	__s32 stack_sz;                              /* bytes valid in stack[] */
	__u32 str_present;                           /* bit i set => str[i] is valid */
	__u64 stack_id;                              /* signature of stack[]; 0 = none. Links
						      * to a HEIMDALL_EV_STACK snapshot record. */
	__u64 stack[HEIMDALL_MAX_STACK_DEPTH];       /* user return addresses */
	char  str[HEIMDALL_STR_SLOTS][HEIMDALL_STR_MAX]; /* string value of args[i] */
	__u32 sock_len;                              /* bytes valid in sock[], 0 = none */
	__u8  sock[HEIMDALL_SOCK_MAX];               /* raw sockaddr (connect/bind/sendto) */
};

/* One stack snapshot, emitted once per distinct stack_id (see above). Carries
 * the user registers and a bounded copy of the thread's stack for off-device
 * DWARF unwinding. The largest ring record — but deduped, so rare. */
struct heimdall_stack_snapshot {
	struct heimdall_hdr h;
	__u64 stack_id;
	__u64 pc, sp, fp, lr;                        /* user pc / sp / x29 / x30 */
	__u32 snap_len;                              /* bytes valid in snap[] (from sp up) */
	__u32 _pad;
	__u8  snap[HEIMDALL_SNAP_MAX];               /* user stack starting at sp */
};

/* An executable, file-backed mapping just appeared (from uprobe_mmap). */
struct heimdall_map_event {
	struct heimdall_hdr h;
	__u64 start;
	__u64 end;
	__u64 pgoff;                                 /* file offset in pages */
	__u64 vm_flags;
	__u64 inode;
	__u32 dev;
	__u32 is_exec;
	char  name[HEIMDALL_MAX_NAME];               /* mapped file basename */
};

/* A range was unmapped (from uprobe_munmap). */
struct heimdall_unmap_event {
	struct heimdall_hdr h;
	__u64 start;
	__u64 end;
};

/* Return value of a previously-emitted syscall, paired by tid (from the
 * kretprobe.multi on __arm64_sys_*). */
struct heimdall_return_event {
	struct heimdall_hdr h;
	__s64 retval;
};

/* Per-process set of executable ranges belonging to the target library, kept in
 * a BPF map so the syscall hook can test stack origin in-kernel. Filled by the
 * loader the moment it sees the library mapped. */
struct heimdall_lib_ranges {
	__u32 count;
	__u32 _pad;
	struct {
		__u64 start;
		__u64 end;
	} r[HEIMDALL_MAX_RANGES];
};

#endif /* HEIMDALL_H */
