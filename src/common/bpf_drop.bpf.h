// SPDX-License-Identifier: GPL-2.0
// Shared BPF drop counter: a per-CPU array that counts ring-buffer allocation
// failures, and the bump_dropped() helper that increments it. Include this once
// per BPF object (not in a shared header that may be transitively included
// multiple times — wrap with an include guard if needed).
#ifndef __ARES_BPF_DROP_H
#define __ARES_BPF_DROP_H

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline void bump_dropped(void)
{
	__u32 k = 0;
	__u64 *c = bpf_map_lookup_elem(&dropped, &k);
	if (c)
		__sync_fetch_and_add(c, 1);
}

#endif /* __ARES_BPF_DROP_H */
