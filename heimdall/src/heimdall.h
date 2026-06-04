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

/* Linux VMA flag (not always macro-defined in vmlinux.h). */
#ifndef HEIMDALL_VM_EXEC
#define HEIMDALL_VM_EXEC 0x00000004UL
#endif

enum heimdall_event_type {
	HEIMDALL_EV_SYSCALL = 1,
	HEIMDALL_EV_MAP     = 2,
	HEIMDALL_EV_UNMAP   = 3,
};

/* Common 16-byte header at the front of every ring-buffer record. `pid` is the
 * thread-group id (process), `tid` the thread. */
struct heimdall_hdr {
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 _pad;
};

/* Entry-only syscall record: number + raw args + user backtrace. */
struct heimdall_syscall_event {
	struct heimdall_hdr h;
	__u64 nr;
	__u64 args[HEIMDALL_SYSCALL_NARGS];
	__s32 stack_sz;                              /* bytes valid in stack[] */
	__u32 _pad2;
	__u64 stack[HEIMDALL_MAX_STACK_DEPTH];       /* user return addresses */
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
