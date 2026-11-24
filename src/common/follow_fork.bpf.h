// SPDX-License-Identifier: GPL-2.0
// Shared follow-fork propagator. Requires pid_filter.bpf.h (target_pids) included
// first, plus vmlinux.h + bpf_tracing.h (BPF_PROG, typed task_struct). When a tracked process forks, the
// child's TGID is inserted into target_pids so PID-attach follows descendants.
// No-op when target_pids is empty (launch/UID mode) → zero cost there. Userspace
// attaches anubee_follow_fork only in PID mode (pids.n > 0 && !no_follow).
#ifndef __ANUBEE_FOLLOW_FORK_BPF_H
#define __ANUBEE_FOLLOW_FORK_BPF_H

// Thread creation fires this tracepoint too. A new thread (pid != tgid) must
// NOT be inserted: target_pids has 64 slots and an app creates far more
// threads than that, so threads would fill the map and every later child
// process insert would fail -- follow-fork would silently stop. tp_btf gives
// the typed child task_struct to tell the two apart (raw tp args carry only
// child_pid). Requires kernel BTF, which every anubee BPF object already needs.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(anubee_follow_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&target_pids, &parent_tgid))
		return 0;
	if (child->pid != child->tgid)
		return 0;   // new thread, not a new process
	__u32 child_tgid = (__u32)child->tgid;
	__u8 one = 1;
	bpf_map_update_elem(&target_pids, &child_tgid, &one, BPF_ANY);
	return 0;
}

#endif /* __ANUBEE_FOLLOW_FORK_BPF_H */
