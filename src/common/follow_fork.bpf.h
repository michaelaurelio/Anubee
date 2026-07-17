// SPDX-License-Identifier: GPL-2.0
// Shared follow-fork propagator. Requires pid_filter.bpf.h (target_pids) included
// first, plus vmlinux.h for the tracepoint ctx. When a tracked process forks, the
// child's TGID is inserted into target_pids so PID-attach follows descendants.
// No-op when target_pids is empty (launch/UID mode) → zero cost there. Userspace
// attaches anubee_follow_fork only in PID mode (pids.n > 0 && !no_follow).
#ifndef __ANUBEE_FOLLOW_FORK_BPF_H
#define __ANUBEE_FOLLOW_FORK_BPF_H

// ponytail: child_pid == tgid for a process fork (the case we want); a new *thread*
// inserts its tid harmlessly — never matched by the tgid-keyed gate.
SEC("tp/sched/sched_process_fork")
int anubee_follow_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&target_pids, &parent_tgid))
		return 0;
	__u32 child = (__u32)ctx->child_pid;
	__u8 one = 1;
	bpf_map_update_elem(&target_pids, &child, &one, BPF_ANY);
	return 0;
}

#endif /* __ANUBEE_FOLLOW_FORK_BPF_H */
