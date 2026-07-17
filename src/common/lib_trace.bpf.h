// SPDX-License-Identifier: GPL-2.0
// Shared BPF capture for native-library load tracing: kprobes on the kernel
// uprobe_mmap / uprobe_munmap that emit lib_map_event / lib_unmap_event for every
// executable, file-backed mapping. Source-shared (not a shared object): #include
// this into each engine's single BPF compilation unit, the same way funcs already
// includes its modules/*.bpf.c. Each engine keeps its own skeleton, preserving the
// "load only your own BPF object" detectability firewall.
//
// Before #include, the including .bpf.c MUST have already included vmlinux.h, the
// bpf helper headers, and "common/lib_trace.h", and MUST provide:
//   - a BPF_MAP_TYPE_RINGBUF map (referenced via LIBTRACE_EVENTS_RB, default `events`)
//   - static __always_inline int uid_matches(void)
// It MAY define LIBTRACE_ON_DROP() to account for a failed ring-buffer reservation.
#ifndef ANUBEE_COMMON_LIB_TRACE_BPF_H
#define ANUBEE_COMMON_LIB_TRACE_BPF_H

#ifndef LIBTRACE_EVENTS_RB
#define LIBTRACE_EVENTS_RB events
#endif
#ifndef LIBTRACE_ON_DROP
#define LIBTRACE_ON_DROP() do { } while (0)
#endif
// Event-type discriminators. Default to the lib_event_type enum, but each engine
// can map them onto its own enum (the syscalls engine numbers UNMAP differently).
#ifndef LIBTRACE_TYPE_MAP
#define LIBTRACE_TYPE_MAP LIB_EV_MAP
#endif
#ifndef LIBTRACE_TYPE_UNMAP
#define LIBTRACE_TYPE_UNMAP LIB_EV_UNMAP
#endif
#ifndef LIBTRACE_EXTRA_GATE
// ponytail: default 0 — every current includer is unaffected; engines with PID
// mode #define this to pid_matches() before including lib_trace.bpf.h.
#define LIBTRACE_EXTRA_GATE() 0
#endif

SEC("kprobe/uprobe_mmap")
int BPF_KPROBE(on_uprobe_mmap, struct vm_area_struct *vma)
{
	if (!uid_matches() && !LIBTRACE_EXTRA_GATE())
		return 0;

	struct file *file = BPF_CORE_READ(vma, vm_file);
	if (file == NULL)
		return 0;

	__u64 vm_flags = BPF_CORE_READ(vma, vm_flags);
	if (!(vm_flags & LIBTRACE_VM_EXEC))
		return 0;

	__u64 id = bpf_get_current_pid_tgid();

	struct lib_map_event *e = bpf_ringbuf_reserve(&LIBTRACE_EVENTS_RB, sizeof(*e), 0);
	if (!e) {
		LIBTRACE_ON_DROP();
		return 0;
	}

	e->h.type = LIBTRACE_TYPE_MAP;
	e->h.pid  = id >> 32;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;

	e->start    = BPF_CORE_READ(vma, vm_start);
	e->end      = BPF_CORE_READ(vma, vm_end);
	e->pgoff    = BPF_CORE_READ(vma, vm_pgoff);
	e->vm_flags = vm_flags;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode != NULL) {
		e->inode = BPF_CORE_READ(inode, i_ino);
		e->dev   = BPF_CORE_READ(inode, i_sb, s_dev);
	} else {
		e->inode = 0;
		e->dev   = 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

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
	if (!uid_matches() && !LIBTRACE_EXTRA_GATE())
		return 0;

	struct file *file = BPF_CORE_READ(vma, vm_file);
	if (file == NULL)
		return 0;

	// Mirror the mmap side: only report executable mappings, so [unlib] pairs
	// with [lib] instead of firing for every file-backed unmap (data/dex/fonts).
	__u64 vm_flags = BPF_CORE_READ(vma, vm_flags);
	if (!(vm_flags & LIBTRACE_VM_EXEC))
		return 0;

	__u64 id = bpf_get_current_pid_tgid();

	struct lib_unmap_event *e = bpf_ringbuf_reserve(&LIBTRACE_EVENTS_RB, sizeof(*e), 0);
	if (!e) {
		LIBTRACE_ON_DROP();
		return 0;
	}

	e->h.type = LIBTRACE_TYPE_UNMAP;
	e->h.pid  = id >> 32;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;
	e->start  = start;
	e->end    = end;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

#endif /* ANUBEE_COMMON_LIB_TRACE_BPF_H */
