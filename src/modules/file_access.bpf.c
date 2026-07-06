// SPDX-License-Identifier: GPL-2.0
// BPF object for the file-access analyzer: trace openat/openat2 syscalls,
// gated in-kernel to 4 fixed path prefixes so only sensitive-storage /
// per-app-data-dir opens reach the ring buffer. Fine-grained classification
// (media subdir / credential filename / foreign-app dir) happens in
// userspace (file_access_classify.c), which has the one piece of context BPF
// doesn't: the traced app's own package name.
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
#include "modules/mod_events.h"

// Bounded prefix compare: path is a fixed-size local/ringbuf buffer (always
// >= 32 bytes), so indexing up to 31 is always safe regardless of prefix
// length; `plen` only controls how much of that fixed window we compare.
static __always_inline int path_has_prefix(const char *path, const char *prefix, int plen)
{
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= plen)
            break;
        if (path[i] != prefix[i])
            return 0;
    }
    return 1;
}

// In-kernel volume gate (load-bearing): unfiltered openat() on Android is
// enormous (every .so/.apk/.oat/cache file at startup). Only forward opens
// under external storage or a per-app data dir; everything else never
// reaches the ring buffer.
static __always_inline int path_is_interesting(const char *path)
{
    if (path_has_prefix(path, "/storage/emulated/", 18)) return 1;
    if (path_has_prefix(path, "/sdcard/", 8))            return 1;
    if (path_has_prefix(path, "/data/data/", 11))        return 1;
    if (path_has_prefix(path, "/data/user/", 11))        return 1;
    return 0;
}

// openat(dirfd, pathname, flags, mode): regs[1]=pathname, regs[2]=flags.
SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(on_openat, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    struct file_access_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // Strip ARM64 MTE tag: bpf_probe_read_user's access_ok() rejects tagged ptrs.
    unsigned long path_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;

    long n = bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)path_ptr);
    if (n <= 0 || !path_is_interesting(e->path)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_FILE_ACCESS;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = e->_pad[3] = 0;
    e->flags  = (__u32)BPF_CORE_READ(regs, regs[2]);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// openat2(dirfd, pathname, struct open_how *how, size_t usize):
// regs[1]=pathname, regs[2]=how. `how->flags` is a u64 at offset 0 of
// open_how -- read it directly rather than depending on that type's BTF
// layout being present/CO-RE-relocatable.
SEC("kprobe/__arm64_sys_openat2")
int BPF_KPROBE(on_openat2, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    struct file_access_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    unsigned long path_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    unsigned long how_ptr  = BPF_CORE_READ(regs, regs[2]) & 0x00FFFFFFFFFFFFFFul;

    long n = bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)path_ptr);
    if (n <= 0 || !path_is_interesting(e->path)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    __u64 flags64 = 0;
    bpf_probe_read_user(&flags64, sizeof(flags64), (void *)how_ptr);

    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_FILE_ACCESS;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = e->_pad[3] = 0;
    e->flags  = (__u32)flags64;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
