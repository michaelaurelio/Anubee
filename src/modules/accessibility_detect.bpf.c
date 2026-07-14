// SPDX-License-Identifier: GPL-2.0
// BPF object for the accessibility-detect analyzer: trace outbound Binder transactions
// to system_server and flag a per-process burst -- accessibility-service
// abuse (overlay/ATS fraud, screen reading, security-prompt bypass) is the
// dominant technique across current Android banking trojans (Mamont, Hook,
// Anatsa, ToxicPanda, RatOn, TrickMo), and it's implemented over Binder IPC.
// v1 is a coarse volume signal only -- no transaction-code decode (parked,
// see docs/superpowers/specs/2026-07-12-mod-accessibility-detect-design.md). Userspace
// classification: src/modules/accessibility_detect_classify.c.
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
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

#define A11Y_WINDOW_NS (5ULL * 1000000000ULL)

// Single-slot config: system_server's pid, resolved once at userspace startup
// (pidof system_server) and pushed BEFORE attach. Unlike the post-attach
// accessibility-grant check (userspace, informational only), this one gates
// in-kernel and must be armed before the first event -- an unresolved (zero)
// value means the gate never matches anything (fail-closed on the gate, not
// a crash).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sys_server_pid_map SEC(".maps");

struct a11y_state {
    __u64 window_start_ns;
    __u32 count;
    __u32 code_ring_head;
    __u32 code_samples[ACCESSIBILITY_DETECT_CODE_RING_LEN];
};

// Per-pid burst state. Only uid/pid-filtered processes ever get an entry (the
// gate runs before any map access), mirrors massdelete_detect's burst_map.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, struct a11y_state);
} a11y_map SEC(".maps");

// Zero-template seed, same reasoning as massdelete_detect's burst_zero: struct
// a11y_state is too large for a safe BPF stack local.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct a11y_state);
} a11y_zero SEC(".maps");

// Record one gated outbound Binder call for the current process; emits an
// accessibility_detect_event and resets the window when the threshold trips. Mirrors
// massdelete_detect.bpf.c's record_touch().
static __always_inline void record_call(__u32 code)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();

    struct a11y_state *st = bpf_map_lookup_elem(&a11y_map, &pid);
    if (!st) {
        __u32 zk = 0;
        struct a11y_state *tmpl = bpf_map_lookup_elem(&a11y_zero, &zk);
        if (!tmpl)
            return;
        if (bpf_map_update_elem(&a11y_map, &pid, tmpl, BPF_NOEXIST) != 0)
            return;
        st = bpf_map_lookup_elem(&a11y_map, &pid);
        if (!st)
            return;
        st->window_start_ns = now;
    }

    if (now - st->window_start_ns > A11Y_WINDOW_NS) {
        st->window_start_ns = now;
        st->count = 0;
        st->code_ring_head = 0;
    }

    __u32 slot = st->code_ring_head & (ACCESSIBILITY_DETECT_CODE_RING_LEN - 1);
    st->code_samples[slot] = code;
    st->code_ring_head++;
    st->count++;

    if (st->count != ACCESSIBILITY_DETECT_THRESHOLD)
        return;

    struct accessibility_detect_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        st->window_start_ns = now;
        st->count = 0;
        st->code_ring_head = 0;
        return;
    }

    __u64 id = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_ACCESSIBILITY_DETECT;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->ts_ns  = now;
    e->touch_count = st->count;
    e->window_ms   = (__u32)((now - st->window_start_ns) / 1000000ULL);
    #pragma unroll
    for (int i = 0; i < ACCESSIBILITY_DETECT_CODE_RING_LEN; i++)
        e->code_samples[i] = st->code_samples[i];   // unused in v1 -- see design doc's parked transaction-code decode
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    st->window_start_ns = now;
    st->count = 0;
    st->code_ring_head = 0;
}

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

    record_call(ctx->code);
    return 0;
}
