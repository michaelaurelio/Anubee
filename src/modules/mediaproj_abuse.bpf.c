// SPDX-License-Identifier: GPL-2.0
// BPF object for the mediaproj-abuse analyzer: a passive per-pid counter of
// outbound Binder transactions to system_server, plus a stub ring buffer.
// The real detection signal is a userspace dumpsys poll thread
// (mediaproj_abuse.c) -- this file's tracepoint only supplies supporting
// context (how Binder-chatty the process was), it never triggers an alert
// itself. a11y-abuse's burst-threshold recipe doesn't transfer to this
// technique: MediaProjection setup is 1-2 discrete Binder calls, not a
// sustained burst, and ongoing frame delivery goes to SurfaceFlinger, not
// system_server, so a burst threshold here would either never fire (high
// threshold) or filter nothing (low threshold).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Stub only -- nothing is ever submitted here. Exists solely because
// ares_analyzer_t.setup() must return a non-NULL struct ring_buffer*, same
// precedent as fileless-exec's events_rb (see fileless_exec.bpf.c's own
// comment on this).
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "modules/mod_events.h"

// system_server's pid, resolved once at userspace startup (pidof
// system_server) and pushed BEFORE attach -- same fail-closed pattern as
// a11y_abuse.bpf.c's sys_server_pid_map. An unresolved (zero) value means
// the gate never matches anything.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sys_server_pid_map SEC(".maps");

// Plain per-pid counter, incremented on every gated outbound Binder call to
// system_server. No window, no threshold, no ringbuf event -- read and
// reset by the userspace poll thread as supporting context only when it
// fires a real (dumpsys-driven) alert.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u64);
} binder_count_map SEC(".maps");

SEC("tp/binder/binder_transaction")
int on_binder_transaction(struct trace_event_raw_binder_transaction *ctx)
{
    if (!uid_matches() && !pid_matches())
        return 0;
    if (ctx->reply)
        return 0;

    __u32 zk = 0;
    __u32 *sys_server_pid = bpf_map_lookup_elem(&sys_server_pid_map, &zk);
    if (!sys_server_pid || *sys_server_pid == 0 || ctx->to_proc != (int)*sys_server_pid)
        return 0;

    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 *count = bpf_map_lookup_elem(&binder_count_map, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&binder_count_map, &pid, &one, BPF_ANY);
    }
    return 0;
}
