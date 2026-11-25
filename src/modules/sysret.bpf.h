// SPDX-License-Identifier: GPL-2.0
// Syscall outcomes for analyzers that record a syscall at entry (kprobe):
// the entry program calls sysret_arm() after submitting its event, and a
// kretprobe on the same syscall calls sysret_emit(ret). Only armed threads get
// a result event, so the kretprobe adds no volume for calls the entry gate
// dropped. Userspace pairs the two by tid (sysret_pend.c).
//
// Include after the events_rb map, bump_dropped() and mod_events.h.
#ifndef ANUBEE_SYSRET_BPF_H
#define ANUBEE_SYSRET_BPF_H

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);     // tid
	__type(value, __u8);
} sysret_armed SEC(".maps");

static __always_inline void sysret_arm(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u8 one = 1;
	bpf_map_update_elem(&sysret_armed, &tid, &one, BPF_ANY);
}

static __always_inline int sysret_emit(long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	if (!bpf_map_lookup_elem(&sysret_armed, &tid))
		return 0;
	bpf_map_delete_elem(&sysret_armed, &tid);

	struct sysret_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}
	e->h.type = MOD_EV_SYSRET;
	e->h.pid  = (__u32)(id >> 32);
	e->h.tid  = tid;
	e->h._pad = 0;
	e->ts_ns  = bpf_ktime_get_ns();
	e->ret    = ret;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#endif
