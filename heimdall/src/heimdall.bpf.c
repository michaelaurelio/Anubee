// heimdall.bpf.c
//
// Syscall tracer for a single Android app, filtered by native-library call
// origin. A syscall event is emitted only when the issuing thread's user
// backtrace passes through one of the target library's executable ranges
// (e.g. a RASP/anti-tamper .so).
//
// Design notes (vs. the frida-strace lineage this is based on):
//
//   * Gating is by UID, not PID. The loader resolves the package's app-UID and
//     installs it BEFORE launching the app, so every thread of the freshly
//     forked app is traced from its very first syscall — closing the startup
//     gap that a launch-then-find-PID approach suffers from. Android sets the
//     app UID during zygote specialization, well before any app/native code
//     runs, so nothing the target library does is missed.
//
//   * The module map is built entirely from uprobe_mmap / uprobe_munmap events.
//     We never read /proc/<pid>/maps. As soon as the target library's text
//     segment is mapped we learn its range live, and because a syscall can only
//     originate from the library after it is mapped, there is no filter gap.
//
//   * Hook is a kprobe on do_el0_svc, the arm64 64-bit syscall dispatcher. This
//     kernel ships CONFIG_FTRACE_SYSCALLS=n on many builds, so we don't rely on
//     raw_syscalls:sys_enter. The syscall number is in x8, args in x0..x5, i.e.
//     the saved user pt_regs->regs[8] and regs[0..5].
//
//   * Entry-only. A kretprobe on do_el0_svc is exhausted by system-wide syscall
//     traffic (maxactive fills instantly), so return values are not captured.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "heimdall.h"

#define MAX_STACK_DEPTH HEIMDALL_MAX_STACK_DEPTH
#define MAX_RANGES      HEIMDALL_MAX_RANGES

char LICENSE[] SEC("license") = "GPL";

// ---- maps ----------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);                 // 4 MB
} events SEC(".maps");

// Single-slot: the app UID to trace, installed by the loader before launch.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target_uid SEC(".maps");

// Per-process (keyed by tgid) executable ranges of the target library. The
// loader populates this in response to the mmap events we emit below.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct heimdall_lib_ranges);
} lib_ranges SEC(".maps");

// Per-syscall mask of which of args[0..3] are const char * (a string). Indexed
// by syscall number; filled by the loader from a built-in table. Used to decide
// which arguments to dereference and copy at entry.
#define ARG_TYPES_MAX 512
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ARG_TYPES_MAX);
	__type(key, __u32);
	__type(value, __u8);
} arg_types SEC(".maps");

// Threads (keyed by tid) with an in-flight syscall we emitted at entry and want
// the return value for. Set at do_el0_svc entry, consumed at __arm64_sys_*
// return. Bounded by live thread count.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} pending SEC(".maps");

// ---- helpers -------------------------------------------------------------

static __always_inline int uid_matches(void)
{
	__u32 key = 0;
	__u32 *want = bpf_map_lookup_elem(&target_uid, &key);
	if (!want || *want == 0)
		return 0;
	return (__u32)bpf_get_current_uid_gid() == *want;
}

// Returns 1 if any captured user return address lands in a target range. Both
// loops are fully unrolled over fixed bounds so every stack[i]/r[j] is a
// constant offset the verifier accepts; `n`/`count` are runtime guards only.
static __always_inline int stack_hits(struct heimdall_lib_ranges *lr, __u64 *stack, int n)
{
	__u32 count = lr->count;
	if (count > MAX_RANGES)
		count = MAX_RANGES;
	if (n > MAX_STACK_DEPTH)
		n = MAX_STACK_DEPTH;

	#pragma clang loop unroll(full)
	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
		if (i >= n)
			continue;
		__u64 ip = stack[i];
		#pragma clang loop unroll(full)
		for (int j = 0; j < MAX_RANGES; j++) {
			if (j < count && ip >= lr->r[j].start && ip < lr->r[j].end)
				return 1;
		}
	}
	return 0;
}

// ---- syscall entry -------------------------------------------------------

SEC("kprobe/do_el0_svc")
int BPF_KPROBE(on_svc_enter, struct pt_regs *user_regs)
{
	if (!uid_matches())
		return 0;

	__u64 id   = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;

	// No target-library range for this process yet => the library isn't
	// mapped, so nothing can have originated from it. Skip before paying for
	// a stack walk.
	struct heimdall_lib_ranges *lr = bpf_map_lookup_elem(&lib_ranges, &tgid);
	if (!lr || lr->count == 0)
		return 0;

	__u64 stack[MAX_STACK_DEPTH];
	long sz = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);
	if (sz <= 0)
		return 0;
	int n = sz / (int)sizeof(__u64);

	if (!stack_hits(lr, stack, n))
		return 0;

	struct heimdall_syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->h.type = HEIMDALL_EV_SYSCALL;
	e->h.pid  = tgid;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;

	__u64 nr = BPF_CORE_READ(user_regs, regs[8]);
	e->nr      = nr;
	e->args[0] = BPF_CORE_READ(user_regs, regs[0]);
	e->args[1] = BPF_CORE_READ(user_regs, regs[1]);
	e->args[2] = BPF_CORE_READ(user_regs, regs[2]);
	e->args[3] = BPF_CORE_READ(user_regs, regs[3]);
	e->args[4] = BPF_CORE_READ(user_regs, regs[4]);
	e->args[5] = BPF_CORE_READ(user_regs, regs[5]);
	e->stack_sz = (__s32)sz;
	__builtin_memcpy(e->stack, stack, sizeof(e->stack));

	// Resolve string arguments. Look up which of args[0..3] are char* for this
	// syscall and copy the pointed-to string out of the caller's memory. The
	// loop is unrolled so each e->str[i] is a constant offset (verifier-safe).
	e->str_present = 0;
	__u32 nr32 = (__u32)e->nr;
	__u8 *maskp = (nr32 < ARG_TYPES_MAX) ? bpf_map_lookup_elem(&arg_types, &nr32) : NULL;
	__u8 mask = maskp ? *maskp : 0;
	if (mask) {
		#pragma clang loop unroll(full)
		for (int i = 0; i < HEIMDALL_STR_SLOTS; i++) {
			if (!((mask >> i) & 1))
				continue;
			long r = bpf_probe_read_user_str(e->str[i], HEIMDALL_STR_MAX,
							 (const void *)e->args[i]);
			if (r > 0)
				e->str_present |= (1u << i);
			else
				e->str[i][0] = '\0';
		}
	}

	bpf_ringbuf_submit(e, 0);

	// Mark this thread so the return probe knows to emit this syscall's result.
	__u32 tid32 = (__u32)id;
	bpf_map_update_elem(&pending, &tid32, &nr, BPF_ANY);
	return 0;
}

// ---- syscall return ------------------------------------------------------
//
// One classic kretprobe program, attached by the loader to a curated list of
// __arm64_sys_* implementation functions (kretprobe.multi/fprobe needs the
// ftrace function tracer, which many Android kernels omit — no
// available_filter_functions). Attaching per-function keeps each function's
// kretprobe instance pool independent, so it avoids the maxactive exhaustion a
// kretprobe on the shared do_el0_svc dispatcher would hit. Gated by the per-tid
// `pending` flag so we only emit returns for syscalls we kept. The SEC target is
// just a placeholder; the loader disables autoattach and attaches the real list.

SEC("kretprobe/__arm64_sys_openat")
int BPF_KRETPROBE(on_sys_exit, long ret)
{
	__u64 id  = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;

	__u64 *p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return 0;
	bpf_map_delete_elem(&pending, &tid);

	struct heimdall_return_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->h.type = HEIMDALL_EV_RETURN;
	e->h.pid  = id >> 32;
	e->h.tid  = tid;
	e->h._pad = 0;
	e->retval = ret;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- module map: mmap / munmap of executable file mappings ---------------

SEC("kprobe/uprobe_mmap")
int BPF_KPROBE(on_uprobe_mmap, struct vm_area_struct *vma)
{
	if (!uid_matches())
		return 0;

	struct file *file = BPF_CORE_READ(vma, vm_file);
	if (file == NULL)
		return 0;

	__u64 vm_flags = BPF_CORE_READ(vma, vm_flags);
	if (!(vm_flags & HEIMDALL_VM_EXEC))
		return 0;

	__u64 id = bpf_get_current_pid_tgid();

	struct heimdall_map_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->h.type = HEIMDALL_EV_MAP;
	e->h.pid  = id >> 32;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;

	e->start    = BPF_CORE_READ(vma, vm_start);
	e->end      = BPF_CORE_READ(vma, vm_end);
	e->pgoff    = BPF_CORE_READ(vma, vm_pgoff);
	e->vm_flags = vm_flags;
	e->is_exec  = 1;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode != NULL) {
		e->inode = BPF_CORE_READ(inode, i_ino);
		e->dev   = BPF_CORE_READ(inode, i_sb, s_dev);
	} else {
		e->inode = 0;
		e->dev   = 0;
	}

	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	e->name[0] = '\0';
	if (name != NULL)
		bpf_probe_read_kernel_str(e->name, sizeof(e->name), name);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/uprobe_munmap")
int BPF_KPROBE(on_uprobe_munmap, struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	if (!uid_matches())
		return 0;

	struct file *file = BPF_CORE_READ(vma, vm_file);
	if (file == NULL)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();

	struct heimdall_unmap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->h.type = HEIMDALL_EV_UNMAP;
	e->h.pid  = id >> 32;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;
	e->start  = start;
	e->end    = end;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
