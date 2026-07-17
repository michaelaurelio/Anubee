// SPDX-License-Identifier: GPL-2.0
// BPF-side coverage counters (CR5): a per-CPU array counting degradation events
// (truncation, depth-cap, pre-arm drop) and cov_bump() to increment a slot.
// Include once per BPF object (mirrors bpf_drop.bpf.h). Firewall: this is a data
// map - no uprobe section - so including it in a quiet object keeps it quiet.
#ifndef __ANUBEE_COVERAGE_BPF_H
#define __ANUBEE_COVERAGE_BPF_H

#include "common/coverage_slots.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COV_SLOT_N);
	__type(key, __u32);
	__type(value, __u64);
} coverage_stats SEC(".maps");

static __always_inline void cov_bump(__u32 slot)
{
	__u64 *c = bpf_map_lookup_elem(&coverage_stats, &slot);
	if (c)
		__sync_fetch_and_add(c, 1);
}

#endif /* __ANUBEE_COVERAGE_BPF_H */
