// SPDX-License-Identifier: GPL-2.0
// BPF object for the massdelete-detect analyzer: trace renameat/renameat2/
// unlinkat syscalls, gated in-kernel to external storage, and flag a
// per-process burst (many touches in a short window) -- the syscall-level
// signature documented for Android crypto-ransomware (Chew et al. 2024:
// renameat -> fstat -> unlinkat, repeated per file). Distinct-path
// estimation and alert classification happen in userspace
// (massdelete_detect_classify.c); this program only gates volume and tracks
// the raw per-pid counter/hash-ring state.
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
#include "common/path_gate.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

#define BURST_WINDOW_NS (10ULL * 1000000000ULL)

// Only external storage -- ransomware has no incentive to encrypt the
// attacking app's own sandboxed /data/data (see design doc Scope).
static __always_inline int path_is_interesting(const char *path)
{
    if (path_has_prefix(path, "/storage/emulated/", 18)) return 1;
    if (path_has_prefix(path, "/sdcard/", 8))            return 1;
    return 0;
}

struct burst_state {
    __u64 window_start_ns;
    __u32 count;
    __u32 ring_head;
    char  paths[MASSDELETE_DETECT_RING_LEN][FILE_PATH_LEN];
};

// Per-pid burst state. Only uid/pid-filtered processes ever get an entry
// (the gate in on_renameat/on_renameat2/on_unlinkat runs before any map
// access), so this stays small regardless of total system process count.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, struct burst_state);
} burst_map SEC(".maps");

// Single always-zero entry, used to seed a fresh burst_map value without
// building a struct burst_state on the BPF stack (path buffer + this struct
// + scratch locals would sit uncomfortably close to the 512-byte verifier
// stack limit) -- bpf_map_update_elem copies straight from this map's
// backing memory instead of a local variable.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct burst_state);
} burst_zero SEC(".maps");

// Record one gated rename/unlink touch for the current process; emits a
// massdelete_detect_event and resets the window when the threshold trips.
static __always_inline void record_touch(const char *path)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();

    struct burst_state *st = bpf_map_lookup_elem(&burst_map, &pid);
    if (!st) {
        __u32 zk = 0;
        struct burst_state *tmpl = bpf_map_lookup_elem(&burst_zero, &zk);
        if (!tmpl)
            return;
        if (bpf_map_update_elem(&burst_map, &pid, tmpl, BPF_NOEXIST) != 0)
            return;
        st = bpf_map_lookup_elem(&burst_map, &pid);
        if (!st)
            return;
        st->window_start_ns = now;
    }

    if (now - st->window_start_ns > BURST_WINDOW_NS) {
        st->window_start_ns = now;
        st->count = 0;
        st->ring_head = 0;
    }

    __u32 slot = st->ring_head & (MASSDELETE_DETECT_RING_LEN - 1);
    bpf_probe_read_kernel_str(st->paths[slot], sizeof(st->paths[slot]), path);
    st->ring_head++;
    st->count++;

    if (st->count != MASSDELETE_DETECT_THRESHOLD)
        return;

    struct massdelete_detect_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        // Reserve failed (ring full): re-arm now so the next touch gets a
        // fresh attempt rather than never emitting again this window.
        bump_dropped();
        st->window_start_ns = now;
        st->count = 0;
        st->ring_head = 0;
        return;
    }

    __u64 id = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_MASSDELETE_DETECT;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->ts_ns  = now;
    e->touch_count = st->count;
    e->window_ms   = (__u32)((now - st->window_start_ns) / 1000000ULL);
    #pragma unroll
    for (int i = 0; i < MASSDELETE_DETECT_RING_LEN; i++)
        __builtin_memcpy(e->paths[i], st->paths[i], FILE_PATH_LEN);
    bpf_probe_read_kernel_str(e->sample_path, sizeof(e->sample_path), path);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    st->window_start_ns = now;
    st->count = 0;
    st->ring_head = 0;
}

// renameat(olddfd, oldpath, newdfd, newpath): regs[3] = newpath (where the
// encrypted output lands -- see design doc Kernel side).
SEC("kprobe/__arm64_sys_renameat")
int BPF_KPROBE(on_renameat, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long path_ptr = BPF_CORE_READ(regs, regs[3]) & 0x00FFFFFFFFFFFFFFul;
    char path[FILE_PATH_LEN];
    long n = bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);
    if (n <= 0 || !path_is_interesting(path))
        return 0;

    record_touch(path);
    return 0;
}

// renameat2(olddfd, oldpath, newdfd, newpath, flags): same arg layout as
// renameat, one extra trailing flags arg we don't need.
SEC("kprobe/__arm64_sys_renameat2")
int BPF_KPROBE(on_renameat2, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long path_ptr = BPF_CORE_READ(regs, regs[3]) & 0x00FFFFFFFFFFFFFFul;
    char path[FILE_PATH_LEN];
    long n = bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);
    if (n <= 0 || !path_is_interesting(path))
        return 0;

    record_touch(path);
    return 0;
}

// unlinkat(dfd, pathname, flags): regs[1] = pathname.
SEC("kprobe/__arm64_sys_unlinkat")
int BPF_KPROBE(on_unlinkat, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long path_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    char path[FILE_PATH_LEN];
    long n = bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);
    if (n <= 0 || !path_is_interesting(path))
        return 0;

    record_touch(path);
    return 0;
}
