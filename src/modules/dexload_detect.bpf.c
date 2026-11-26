// SPDX-License-Identifier: GPL-2.0
// BPF object for the dexload-detect analyzer: payload files dropped by the
// traced app and what happens to them.
//   drop   -- kprobe/vfs_write: the app writes, at offset 0 of a regular
//             file, bytes starting with a DEX/CDEX/ZIP/ELF header (the
//             approach of Tracee's magic_write signal).
//   load   -- kprobe/security_mmap_file: any process maps a dropped file
//             (ART maps a DEX/APK it loads; the linker maps a .so). Again
//             once mapped executable.
//   delete -- kprobe/security_inode_unlink: a dropped file is unlinked
//             (the "load then delete" anti-forensics step).
//   memload -- kprobe/__arm64_sys_prctl: ART names an anonymous region it
//             holds a DEX in -- "dalvik-DEX data" (InMemoryDexClassLoader and
//             other byte-array loads) or "dalvik-classes*.dex extracted in
//             memory from <file>". The DEX is copied in after the naming;
//             userspace reads it from /proc/<pid>/mem once its header is valid.
// Dropped files are keyed by (device, inode), so renames keep matching.
// Userspace (dexload_detect.c) classifies the header precisely, joins the
// path and saves a copy of the payload. All kprobes: nothing is written to
// the target.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

#define DL_S_IFMT   0170000
#define DL_S_IFREG  0100000
#define DL_PROT_EXEC 0x4
#define DL_WALK_MAX  32   // components + mount crossings

#define DL_LOADED      0x1
#define DL_LOADED_EXEC 0x2

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct dexload_key);
	__type(value, struct dexload_val);
} dexload_files SEC(".maps");

static __always_inline int dl_magic(const unsigned char *b)
{
	return (b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') ||
	       (b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4) ||
	       (b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n') ||
	       (b[0] == 'c' && b[1] == 'd' && b[2] == 'e' && b[3] == 'x');
}

static __always_inline void dl_key_of(struct inode *inode, struct dexload_key *k)
{
	k->ino  = BPF_CORE_READ(inode, i_ino);
	k->dev  = BPF_CORE_READ(inode, i_sb, s_dev);
	k->_pad = 0;
}

// The event is built in a per-CPU scratch slot (too big for the stack) and
// copied to the ring with bpf_ringbuf_output.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dexload_detect_event);
} dl_scratch SEC(".maps");

// Leaf-first path of (dentry, vfsmount), crossing mount points up to the
// root of the caller's mount namespace -- what d_path() does, bounded. One
// bpf_loop step per component or mount crossing (a plain loop with these
// branches exceeds the verifier's complexity limit).
struct dl_walk_ctx {
	__u64 d;      // struct dentry *
	__u64 mnt;    // struct mount *
	__u32 n;
	__u32 done;
};

static long dl_walk_step(__u32 i, struct dl_walk_ctx *c)
{
	__u32 z = 0;
	struct dexload_detect_event *e = bpf_map_lookup_elem(&dl_scratch, &z);
	if (!e)
		return 1;
	struct dentry *d   = (struct dentry *)c->d;
	struct mount *mnt  = (struct mount *)c->mnt;
	struct dentry *root   = BPF_CORE_READ(mnt, mnt.mnt_root);
	struct dentry *parent = BPF_CORE_READ(d, d_parent);
	if (d == root || d == parent) {
		struct mount *mp = BPF_CORE_READ(mnt, mnt_parent);
		if (!mp || mp == mnt) {
			c->done = 1;
			return 1;
		}
		c->d   = (__u64)BPF_CORE_READ(mnt, mnt_mountpoint);
		c->mnt = (__u64)mp;
		return 0;
	}
	if (c->n >= DEXLOAD_COMP_N)
		return 1;
	const unsigned char *name = BPF_CORE_READ(d, d_name.name);
	bpf_probe_read_kernel_str(e->comp[c->n & (DEXLOAD_COMP_N - 1)], DEXLOAD_COMP_LEN, name);
	c->n++;
	c->d = (__u64)parent;
	return 0;
}

static __always_inline void dl_walk(struct dexload_detect_event *e,
                                    struct dentry *d, struct vfsmount *vm)
{
	struct dl_walk_ctx c = {
		.d   = (__u64)d,
		.mnt = (__u64)((void *)vm - bpf_core_field_offset(struct mount, mnt)),
	};
	bpf_loop(DL_WALK_MAX, dl_walk_step, &c, 0);
	e->ncomp     = c.n;
	e->truncated = !c.done;
}

static __always_inline struct dexload_detect_event *dl_begin(__u8 stage, const struct dexload_key *k)
{
	__u32 z = 0;
	struct dexload_detect_event *e = bpf_map_lookup_elem(&dl_scratch, &z);
	if (!e)
		return NULL;
	__u64 id = bpf_get_current_pid_tgid();
	e->h.type  = MOD_EV_DEXLOAD_DETECT;
	e->h.pid   = id >> 32;
	e->h.tid   = (__u32)id;
	e->h._pad  = 0;
	e->ts_ns   = bpf_ktime_get_ns();
	e->ino     = k->ino;
	e->dev     = k->dev;
	e->stage   = stage;
	e->exec    = 0;
	e->ncomp   = 0;
	e->truncated = 0;
	e->addr    = 0;
	e->len     = 0;
	__builtin_memset(e->head, 0, sizeof(e->head));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void dl_send(struct dexload_detect_event *e)
{
	if (bpf_ringbuf_output(&events_rb, e, sizeof(*e), 0))
		bump_dropped();
}

// vfs_write(file, buf, count, pos): every write()/pwrite64() to a file.
SEC("kprobe/vfs_write")
int BPF_KPROBE(on_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos)
{
	if (!uid_matches() && !pid_matches())
		return 0;
	if (count < 4 || !pos)
		return 0;
	loff_t off = 0;
	if (bpf_probe_read_kernel(&off, sizeof(off), pos) || off != 0)
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode || (BPF_CORE_READ(inode, i_mode) & DL_S_IFMT) != DL_S_IFREG)
		return 0;

	unsigned char head[8] = {};
	const void *ubuf = (const void *)((unsigned long)buf & 0x00FFFFFFFFFFFFFFul);
	if (bpf_probe_read_user(head, count >= 8 ? 8 : 4, ubuf) || !dl_magic(head))
		return 0;

	struct dexload_key k;
	dl_key_of(inode, &k);
	struct dexload_val *old = bpf_map_lookup_elem(&dexload_files, &k);
	if (old && !old->deleted)   // rewrite of a file already reported
		return 0;
	struct dexload_val v = {
		.drop_ts_ns = bpf_ktime_get_ns(),
		.pid        = bpf_get_current_pid_tgid() >> 32,
	};
	bpf_map_update_elem(&dexload_files, &k, &v, BPF_ANY);

	struct dexload_detect_event *e = dl_begin(DEXLOAD_STAGE_DROP, &k);
	if (!e)
		return 0;
	__builtin_memcpy(e->head, head, sizeof(head));
	dl_walk(e, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt));
	dl_send(e);
	return 0;
}

// security_mmap_file(file, prot, flags): any process mapping a dropped file
// (no target gate -- a helper process loading the payload counts too).
SEC("kprobe/security_mmap_file")
int BPF_KPROBE(on_mmap_file, struct file *file, unsigned long prot)
{
	if (!file)
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	struct dexload_key k;
	dl_key_of(inode, &k);
	struct dexload_val *v = bpf_map_lookup_elem(&dexload_files, &k);
	if (!v)
		return 0;
	int exec = (prot & DL_PROT_EXEC) != 0;
	if ((v->loaded & DL_LOADED) && (!exec || (v->loaded & DL_LOADED_EXEC)))
		return 0;
	v->loaded |= DL_LOADED | (exec ? DL_LOADED_EXEC : 0);

	struct dexload_detect_event *e = dl_begin(DEXLOAD_STAGE_LOAD, &k);
	if (!e)
		return 0;
	e->exec = exec;
	dl_walk(e, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt));
	dl_send(e);
	return 0;
}

// security_inode_unlink(dir, dentry): a dropped file is being deleted.
SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(on_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;
	struct dexload_key k;
	dl_key_of(inode, &k);
	struct dexload_val *v = bpf_map_lookup_elem(&dexload_files, &k);
	if (!v || v->deleted)
		return 0;
	v->deleted = 1;

	struct dexload_detect_event *e = dl_begin(DEXLOAD_STAGE_DELETE, &k);
	if (!e)
		return 0;
	dl_send(e);
	return 0;
}

// prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, name): how ART's MemMap
// names its anonymous regions. Args from pt_regs (syscall-entry kprobe);
// the name pointer is tag-stripped before the user read.
#define DL_PR_SET_VMA           0x53564d41UL   // "SVMA", <linux/prctl.h>
#define DL_PR_SET_VMA_ANON_NAME 0UL

SEC("kprobe/__arm64_sys_prctl")
int BPF_KPROBE(on_prctl, const struct pt_regs *regs)
{
	if (!uid_matches() && !pid_matches())
		return 0;
	if (BPF_CORE_READ(regs, regs[0]) != DL_PR_SET_VMA ||
	    BPF_CORE_READ(regs, regs[1]) != DL_PR_SET_VMA_ANON_NAME)
		return 0;
	char n[16] = {};
	unsigned long np = BPF_CORE_READ(regs, regs[4]) & 0x00FFFFFFFFFFFFFFul;
	if (bpf_probe_read_user(n, sizeof(n), (void *)np))
		return 0;
	// "dalvik-DEX data" / "dalvik-classes..."
	if (!(n[0] == 'd' && n[1] == 'a' && n[2] == 'l' && n[3] == 'v' && n[4] == 'i' &&
	      n[5] == 'k' && n[6] == '-'))
		return 0;
	int dexdata = n[7] == 'D' && n[8] == 'E' && n[9] == 'X' && n[10] == ' ' && n[11] == 'd';
	int classes = n[7] == 'c' && n[8] == 'l' && n[9] == 'a' && n[10] == 's' && n[11] == 's';
	if (!dexdata && !classes)
		return 0;

	struct dexload_key k = {};
	struct dexload_detect_event *e = dl_begin(DEXLOAD_STAGE_MEMLOAD, &k);
	if (!e)
		return 0;
	e->addr  = BPF_CORE_READ(regs, regs[2]);
	e->len   = BPF_CORE_READ(regs, regs[3]);
	e->ncomp = 1;
	// whole name across comp[]: the kernel may reject it (over 80 bytes), and
	// then this is the only record of which file the region was unpacked from
	bpf_probe_read_user_str(&e->comp[0][0], sizeof(e->comp), (void *)np);
	dl_send(e);
	return 0;
}
