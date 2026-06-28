// SPDX-License-Identifier: GPL-2.0
// BPF object for `ares correlate`: span-gated function->syscall correlation.
//
// Entry uprobes (attached by the loader at spec'd function offsets) push a per-tid
// span and emit a FUNC event. A kprobe on do_el0_svc tags each syscall issued
// while a span is open with that innermost span and emits a SYSCALL event. The
// span stack (push / SP-reconcile / top-id) is the shared common/span_stack.bpf.h.
//
// This object carries the uprobe, so it is the LOUD path; the quiet engines never
// load it (detectability firewall).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "correlate.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

#include "common/uid_filter.bpf.h"   // target_uids map + uid_matches()
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"

#define NUM_ARGS CORR_NUM_ARGS
#include "common/span_stack.bpf.h"

// Function entry: open a span, emit FUNC.
SEC("uprobe")
int BPF_KPROBE(corr_uprobe_entry, long a1, long a2, long a3, long a4,
               long a5, long a6, long a7, long a8)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(id >> 32);
    __u32 tid = (__u32)id;

    long raw[NUM_ARGS] = { a1, a2, a3, a4, a5, a6, a7, a8 };
    __u64 entry_sp = (__u64)PT_REGS_SP(ctx);
    span_stack_reconcile(tid, entry_sp);
    __u64 sid = span_stack_push(tid, (__u64)PT_REGS_IP(ctx), entry_sp,
                                bpf_ktime_get_ns(), raw);
    if (!sid)
        return 0;

    // Read back the just-pushed top frame for its parent_span.
    __u64 parent = 0;
    __u32 *dp = bpf_map_lookup_elem(&span_depth, &tid);
    if (dp && *dp >= 1) {
        struct frame_key tk = { .tid = tid, .slot = *dp - 1 };
        struct span_frame *tf = bpf_map_lookup_elem(&span_frames, &tk);
        if (tf) parent = tf->parent_span;
    }

    struct corr_func_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->h.type = CORR_EV_FUNC;
    e->h.pid  = pid;
    e->h.tid  = tid;
    e->h._pad = 0;
    e->span        = sid;
    e->parent_span = parent;
    e->entry_addr  = (__u64)PT_REGS_IP(ctx);
    #pragma unroll
    for (int i = 0; i < NUM_ARGS; i++)
        e->args[i] = (__u64)raw[i];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Syscall entry: if a span is open on this thread, tag it and emit.
SEC("kprobe/do_el0_svc")
int BPF_KPROBE(corr_on_svc, struct pt_regs *user_regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(id >> 32);
    __u32 tid = (__u32)id;

    __u64 sp   = BPF_CORE_READ(user_regs, sp);
    __u64 span = span_stack_top_id(tid, sp);
    if (!span)
        return 0;

    struct corr_syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->h.type = CORR_EV_SYSCALL;
    e->h.pid  = pid;
    e->h.tid  = tid;
    e->h._pad = 0;
    e->span    = span;
    e->nr      = BPF_CORE_READ(user_regs, regs[8]);
    e->args[0] = BPF_CORE_READ(user_regs, regs[0]);
    e->args[1] = BPF_CORE_READ(user_regs, regs[1]);
    e->args[2] = BPF_CORE_READ(user_regs, regs[2]);
    e->args[3] = BPF_CORE_READ(user_regs, regs[3]);
    e->args[4] = BPF_CORE_READ(user_regs, regs[4]);
    e->args[5] = BPF_CORE_READ(user_regs, regs[5]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
