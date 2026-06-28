// SPDX-License-Identifier: GPL-2.0
// Shared kernel-side target-PID filter. Mirror of uid_filter.bpf.h. The loader
// inserts each target TGID (key=tgid, value=1) before attach; pid_matches() is set
// membership on the running task's TGID. Source-shared across engines; pairs with
// the `uid_matches() || pid_matches()` gate. follow_fork.bpf.h extends this map.
// Include once per .bpf.c, before any use of pid_matches().
#ifndef __ARES_PID_FILTER_BPF_H
#define __ARES_PID_FILTER_BPF_H

// ponytail: 64 slots — covers a target PID set incl. followed children; bump if more.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

static __always_inline int pid_matches(void)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&target_pids, &tgid) != NULL;
}

#endif /* __ARES_PID_FILTER_BPF_H */
