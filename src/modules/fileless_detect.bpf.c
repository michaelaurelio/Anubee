// SPDX-License-Identifier: GPL-2.0
// BPF object for the fileless-detect analyzer: executable memory that has
// no file behind it -- the mechanism behind native packers/unpackers,
// in-memory second stages and exec-from-memfd. Three signals, all kprobes:
//   anon_exec_mmap -- do_mmap entry/return: an anonymous mapping created
//                     executable. Recorded in pending_map; userspace graduates
//                     it after FILELESS_DETECT_GRACE_NS unless the region's
//                     kernel-held name (/proc/<pid>/maps) is ART's own.
//   mprotect_exec  -- security_file_mprotect: anonymous, anonymous-shared or
//                     memfd memory gaining PROT_EXEC (anonymous memory starts
//                     zeroed, so code was written into it first).
//   memfd_exec     -- security_mmap_file: a memfd mapped executable,
//                     including execve of a memfd (fexecve).
// ART's JIT regions are recognised by name ("dalvik-*" anonymous/shmem
// names, memfd "jit-*"), read from the vma in the kernel for the last two.
// DexClassLoader/DEX loading runs through ART's own regions and is
// dexload-detect's job.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 1024 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

// enum fl_kind values (fileless_detect_parse.h is userspace-only).
#define FL_KIND_MPROTECT_EXEC 2
#define FL_KIND_MEMFD_EXEC    3

#define FILELESS_PROT_EXEC 0x4UL   // PROT_EXEC (do_mmap/mprotect take the userspace values)
#define FILELESS_VM_EXEC   0x4UL   // VM_EXEC

// Per-tid scratch: do_mmap's real args, captured at entry and consumed at
// return -- a kretprobe alone can't see entry args (registers are
// clobbered by the callee), same reasoning as every other entry/exit
// correlation map in this codebase.
struct fileless_entry_scratch {
    __u64 len;
    __u32 anon;   // 1 if file == NULL at entry, else 0
    __u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);                          // pid_tgid
	__type(value, struct fileless_entry_scratch);
} entry_scratch SEC(".maps");

// Candidate anon+exec mappings awaiting graduation: the userspace dispatcher
// tick takes FILELESS_DETECT_GRACE_NS-old entries, reads the region's name
// and drops ART's. At capacity (1024) a new candidate is not inserted
// (BPF_MAP_TYPE_HASH has no eviction) -- a known gap.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct fileless_pending_key);
	__type(value, struct fileless_pending_val);
} pending_map SEC(".maps");

SEC("kprobe/do_mmap")
int BPF_KPROBE(on_do_mmap_entry, struct file *file, unsigned long addr,
               unsigned long len, unsigned long prot, unsigned long flags)
{
    if (!uid_matches() && !pid_matches())
        return 0;
    if (!(prot & FILELESS_PROT_EXEC))
        return 0;

    struct fileless_entry_scratch sc = {
        .len  = len,
        .anon = (file == NULL) ? 1u : 0u,
    };
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&entry_scratch, &id, &sc, BPF_ANY);
    return 0;
}

SEC("kretprobe/do_mmap")
int BPF_KRETPROBE(on_do_mmap_exit, long ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct fileless_entry_scratch *sc = bpf_map_lookup_elem(&entry_scratch, &id);
    if (!sc)
        return 0;
    struct fileless_entry_scratch local = *sc;
    bpf_map_delete_elem(&entry_scratch, &id);   // always clear scratch, hit or miss

    if (!local.anon || ret <= 0)
        return 0;

    struct fileless_pending_key k = {
        .pid  = (__u32)(id >> 32),
        .addr = (__u64)ret,
    };
    struct fileless_pending_val v = {
        .ts_ns = bpf_ktime_get_ns(),
        .size  = local.len,
    };
    bpf_get_current_comm(&v.comm, sizeof(v.comm));
    bpf_map_update_elem(&pending_map, &k, &v, BPF_ANY);
    return 0;
}

// ---- name-based ART recognition ----------------------------------------

static __always_inline int fl_is_art_name(const char *n)
{
	if (n[0] == 'd' && n[1] == 'a' && n[2] == 'l' && n[3] == 'v' && n[4] == 'i'
	    && n[5] == 'k' && n[6] == '-')
		return 1;
	// memfd:jit-cache / memfd:jit-zygote-cache
	return n[0] == 'm' && n[1] == 'e' && n[2] == 'm' && n[3] == 'f' && n[4] == 'd'
	       && n[5] == ':' && n[6] == 'j' && n[7] == 'i' && n[8] == 't' && n[9] == '-';
}

static __always_inline int fl_is_memfd_name(const char *n)
{
	return n[0] == 'm' && n[1] == 'e' && n[2] == 'm' && n[3] == 'f' && n[4] == 'd'
	       && n[5] == ':';
}

// "dev/zero" is the backing file of a MAP_SHARED|MAP_ANONYMOUS mapping.
static __always_inline int fl_is_shmem_zero_name(const char *n)
{
	return n[0] == 'd' && n[1] == 'e' && n[2] == 'v' && n[3] == '/' && n[4] == 'z'
	       && n[5] == 'e' && n[6] == 'r' && n[7] == 'o' && n[8] == '\0';
}

static __always_inline void fl_file_name(struct file *f, char *out)
{
	const unsigned char *n = BPF_CORE_READ(f, f_path.dentry, d_name.name);
	bpf_probe_read_kernel_str(out, FILELESS_DETECT_TAG_LEN, n);
}

static __always_inline void fl_send(__u32 kind, __u64 start, __u64 size, __u64 ino,
                                    const char *name)
{
	struct fileless_detect_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return;
	}
	__u64 id = bpf_get_current_pid_tgid();
	e->h.type = MOD_EV_FILELESS_DETECT;
	e->h.pid  = id >> 32;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;
	e->ts_ns  = bpf_ktime_get_ns();
	e->start  = start;
	e->size   = size;
	e->ino    = ino;
	e->kind   = kind;
	e->_pad   = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->anon_name, name, FILELESS_DETECT_TAG_LEN);
	bpf_ringbuf_submit(e, 0);
}

// mprotect(..., PROT_EXEC) on anonymous / anonymous-shared / memfd memory.
SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(on_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
               unsigned long prot)
{
	if (!uid_matches() && !pid_matches())
		return 0;
	if (!(prot & FILELESS_PROT_EXEC))
		return 0;
	if (BPF_CORE_READ(vma, vm_flags) & FILELESS_VM_EXEC)
		return 0;   // already executable

	char name[FILELESS_DETECT_TAG_LEN] = {};
	__u64 ino = 0;
	struct file *f = BPF_CORE_READ(vma, vm_file);
	if (f) {
		fl_file_name(f, name);
		if (!fl_is_memfd_name(name) && !fl_is_shmem_zero_name(name))
			return 0;   // a real file (e.g. text relocations) -- not fileless
		if (fl_is_memfd_name(name))
			ino = BPF_CORE_READ(f, f_inode, i_ino);
		else
			name[0] = '\0';
	}
	if (!name[0] && bpf_core_field_exists(vma->anon_name)) {
		struct anon_vma_name *an = BPF_CORE_READ(vma, anon_name);
		if (an)
			bpf_probe_read_kernel_str(name, sizeof(name), &an->name);
	}
	if (fl_is_art_name(name))
		return 0;

	__u64 start = BPF_CORE_READ(vma, vm_start);
	fl_send(FL_KIND_MPROTECT_EXEC, start, BPF_CORE_READ(vma, vm_end) - start, ino, name);
	return 0;
}

// mmap(..., PROT_EXEC, ..., memfd) -- also how execve maps a memfd's segments.
SEC("kprobe/security_mmap_file")
int BPF_KPROBE(on_mmap_file, struct file *file, unsigned long prot)
{
	if (!file || !(prot & FILELESS_PROT_EXEC))
		return 0;
	if (!uid_matches() && !pid_matches())
		return 0;
	char name[FILELESS_DETECT_TAG_LEN] = {};
	fl_file_name(file, name);
	if (!fl_is_memfd_name(name) || fl_is_art_name(name))
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	fl_send(FL_KIND_MEMFD_EXEC, 0, BPF_CORE_READ(inode, i_size),
	        BPF_CORE_READ(inode, i_ino), name);
	return 0;
}
