// SPDX-License-Identifier: GPL-2.0
// BPF object for the proc-event analyzer: trace process fork and exit events.
// Standalone module with no dependency on the funcs engine.
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

SEC("tp/sched/sched_process_fork")
int on_proc_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	if (!uid_matches() && !pid_matches())
		return 0;

	struct spawn_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id     = bpf_get_current_pid_tgid();
	e->h.type    = MOD_EV_SPAWN;
	e->h.pid     = (__u32)(id >> 32);
	e->h.tid     = (__u32)id;
	e->h._pad    = 0;
	e->child_pid = (__u32)ctx->child_pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}


struct trace_event_raw_sched_process_exit;

SEC("tp/sched/sched_process_exit")
int on_proc_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	if (!uid_matches() && !pid_matches())
		return 0;

	__u64 id  = bpf_get_current_pid_tgid();
	pid_t pid = (__u32)(id >> 32);
	pid_t tid = (__u32)id;

	// Skip thread exits; only emit PROC_EXIT for the process main thread
	if (pid != tid)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int raw_exit = BPF_CORE_READ(task, exit_code);

	struct proc_exit_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->h.type    = MOD_EV_PROC_EXIT;
	e->h.pid     = pid;
	e->h.tid     = tid;
	e->h._pad    = 0;
	e->exit_code = raw_exit;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
