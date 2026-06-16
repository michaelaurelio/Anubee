// SPDX-License-Identifier: GPL-2.0
// BPF object for `ares dump`: trace every native library (.so) an app loads so
// the loader can dump matching modules from live memory.
//
// Per-engine BPF (detectability firewall): this is its own object, not the
// uprobe engine's. Gating is by UID, installed by the loader BEFORE launch, so
// every thread of the freshly forked app is seen from its first mapping. The
// mmap/munmap capture is the shared probe in common/lib_trace.bpf.h.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common/lib_trace.h"

char LICENSE[] SEC("license") = "GPL";

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

static __always_inline int uid_matches(void)
{
	__u32 key = 0;
	__u32 *want = bpf_map_lookup_elem(&target_uid, &key);
	if (!want || *want == 0)
		return 0;
	return (__u32)bpf_get_current_uid_gid() == *want;
}

#include "common/lib_trace.bpf.h"
