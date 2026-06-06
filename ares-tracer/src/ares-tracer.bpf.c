#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ares-tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_uid SEC(".maps");


// Determine if a value is a user-space pointer (heuristic) -> CHANGE LATER
static __always_inline bool is_user_ptr(unsigned long val)
{
    unsigned long untagged = val & 0x00FFFFFFFFFFFFFFUL;
    return untagged > 0x10000UL && untagged < 0x800000000000UL;
}


// Helper for UID-based filtering
static __always_inline int uid_matches(void)
{
	__u32 key = 0;
	__u32 *want = bpf_map_lookup_elem(&target_uid, &key);
	if (!want || *want == 0)
		return 0;
	return (__u32)bpf_get_current_uid_gid() == *want;
}

static __always_inline int uid_matches_or_unset(void)
{
	__u32 key = 0;
	__u32 *want = bpf_map_lookup_elem(&target_uid, &key);
	if (!want || *want == 0)
		return 1;
	return (__u32)bpf_get_current_uid_gid() == *want;
}


// Function entry handler to attach uprobe
SEC("uprobe")
int BPF_KPROBE(uprobe_open, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
    if (!uid_matches_or_unset())
        return 0;

    // Initializations stuff
    struct task_struct *task;
    struct event *e;
    pid_t pid;
    pid_t tid;

    pid = bpf_get_current_pid_tgid() >> 32;
    tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;


    // Reserve space in ring buffer for event
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;


    // Fill event data
    task = (struct task_struct *)bpf_get_current_task();

    e->h.type = ARES_EVENT_CALL;
    e->h.pid = pid;
    e->h.tid = tid;
	e->h._pad = 0;
    e->entry_addr = (__u64)PT_REGS_IP(ctx);
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->exit_event = false;

    // TEMP STUFF, FIX TOMORROW
    long raw[NUM_ARGS] = {a1, a2, a3, a4, a5, a6, a7, a8};
    #pragma unroll
    for (int i = 0; i < NUM_ARGS; i++) {
        e->args[i] = (unsigned long)raw[i];
        e->is_str[i] = 0;
        if (is_user_ptr((unsigned long)raw[i])) {
            long n = bpf_probe_read_user_str(e->strings[i], MAX_STR_LEN, (void*)raw[i]);
            if (n > 1)
                e->is_str[i] = 1;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/uprobe_mmap")
int BPF_KPROBE(on_uprobe_mmap, struct vm_area_struct *vma)
{
    // Filter by UID
	if (!uid_matches())  
		return 0;

    // Filter out anonymous mappings
	struct file *file = BPF_CORE_READ(vma, vm_file);
	if (file == NULL)
		return 0;

    // Skip non-executable mappings
	__u64 vm_flags = BPF_CORE_READ(vma, vm_flags);
	if (!(vm_flags & ARES_VM_EXEC))
		return 0;

    // Reserve ring buffer slot
	struct map_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e)
		return 0;

    // Fill shared header
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

	e->h.type = ARES_EVENT_MAP;
	e->h.pid  = pid;
	e->h.tid  = tid;
	e->h._pad = 0;

    // Fill event-specific data
	e->start    = BPF_CORE_READ(vma, vm_start);
	e->end      = BPF_CORE_READ(vma, vm_end);
	e->pgoff    = BPF_CORE_READ(vma, vm_pgoff);
	e->vm_flags = vm_flags;

    // Store inode and device info 
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode != NULL) {
		e->inode = BPF_CORE_READ(inode, i_ino);
		e->dev   = BPF_CORE_READ(inode, i_sb, s_dev);
	} else {
		e->inode = 0;
		e->dev   = 0;
	}

    // Store file basename
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	e->name[0] = '\0';
	if (name != NULL)
		bpf_probe_read_kernel_str(e->name, sizeof(e->name), name);

    // Submit event to ring buffer
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

    // Reserve ring buffer slot
	struct map_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

	e->h.type = ARES_EVENT_UNMAP;
	e->h.pid  = pid;
	e->h.tid  = tid;
	e->h._pad = 0;
	e->start  = start;
	e->end    = end;

	bpf_ringbuf_submit(e, 0);
	return 0;
}