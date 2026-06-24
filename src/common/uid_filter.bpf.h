// SPDX-License-Identifier: GPL-2.0
// Shared kernel-side target-UID filter. The loader inserts each app UID (key=uid,
// value=1) BEFORE launch/attach; uid_matches() is set membership. Source-shared
// across every engine's own BPF object (detectability firewall keeps objects
// separate, not source). Include once per .bpf.c, before any use of uid_matches().
#ifndef __ARES_UID_FILTER_BPF_H
#define __ARES_UID_FILTER_BPF_H

// ponytail: 32 slots — ample for one app's UID set; bump only if tracking >32 UIDs.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, __u32);
	__type(value, __u8);
} target_uids SEC(".maps");

static __always_inline int uid_matches(void)
{
	__u32 uid = (__u32)bpf_get_current_uid_gid();
	return bpf_map_lookup_elem(&target_uids, &uid) != NULL;
}

#endif /* __ARES_UID_FILTER_BPF_H */
