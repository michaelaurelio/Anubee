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
#include "common/bpf_drop.bpf.h"     // dropped map + bump_dropped()

#define NUM_ARGS CORR_NUM_ARGS
#include "common/span_stack.bpf.h"

// Per-syscall string-arg mask / sockaddr-arg index, mirrored from syscalls.bpf.c
// (same shape, same install-time source tables in correlate.c).
#define ARG_TYPES_MAX 512
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ARG_TYPES_MAX);
    __type(key, __u32);
    __type(value, __u8);
} arg_types SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ARG_TYPES_MAX);
    __type(key, __u32);
    __type(value, __u8);
} sock_args SEC(".maps");

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
    if (!e) {
        bump_dropped();
        return 0;
    }
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

// Function return (only attached when --returns is given): authoritatively pop
// the span the instant its function returns, independent of SP behavior.
// Mirrors funcs.bpf.c's uretprobe_open (same span_frames/span_depth shapes).
SEC("uretprobe")
int BPF_KRETPROBE(corr_uretprobe_ret)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(id >> 32);
    __u32 tid = (__u32)id;
    __u64 now = bpf_ktime_get_ns();

    __u32 *dp = bpf_map_lookup_elem(&span_depth, &tid);
    if (!dp || *dp == 0)
        return 0;
    __u32 top = *dp - 1;
    struct frame_key fk = { .tid = tid, .slot = top };
    struct span_frame *saved = bpf_map_lookup_elem(&span_frames, &fk);
    if (!saved) {
        span_depth_set(tid, top);  // depth/frame desync: shrink and bail
        return 0;
    }

    struct corr_func_return_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
    } else {
        e->h.type = CORR_EV_FUNC_RETURN;
        e->h.pid  = pid;
        e->h.tid  = tid;
        e->h._pad = 0;
        e->span       = saved->span_id;
        e->entry_addr = saved->entry_addr;
        e->retval     = (__u64)PT_REGS_RC(ctx);
        e->elapsed_ns = now - saved->timestamp;
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&span_frames, &fk);
    span_depth_set(tid, top);      // authoritative pop
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
    if (!e) {
        bump_dropped();
        return 0;
    }
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

    // Resolve string arguments (copied from syscalls.bpf.c: same mask -> str[]
    // shape, unrolled so each e->str[i] is a constant offset).
    e->str_present = 0;
    __u32 nr32 = (__u32)e->nr;
    __u8 *maskp = (nr32 < ARG_TYPES_MAX) ? bpf_map_lookup_elem(&arg_types, &nr32) : NULL;
    __u8 mask = maskp ? *maskp : 0;
    if (mask) {
        #pragma clang loop unroll(full)
        for (int i = 0; i < CORR_STR_SLOTS; i++) {
            if (!((mask >> i) & 1))
                continue;
            long r = bpf_probe_read_user_str(e->str[i], CORR_STR_MAX,
                             (const void *)e->args[i]);
            if (r > 0)
                e->str_present |= (1u << i);
            else
                e->str[i][0] = '\0';
        }
    }

    // Capture the sockaddr for connect/bind/sendto (copied from syscalls.bpf.c).
    e->sock_len = 0;
    __u8 *sap = (nr32 < ARG_TYPES_MAX) ? bpf_map_lookup_elem(&sock_args, &nr32) : NULL;
    __u8 sidx = sap ? *sap : 0;
    if (sidx) {
        const void *ptr = NULL;
        __u64 alen = 0;
        #pragma clang loop unroll(full)
        for (int j = 0; j < CORR_SYS_ARGS - 1; j++) {
            if (sidx == (__u8)(j + 1)) {
                ptr = (const void *)e->args[j];
                alen = e->args[j + 1];
            }
        }
        if (ptr && alen) {
            __u32 cnt = (__u32)alen & (CORR_SOCK_MAX - 1);
            if (cnt && bpf_probe_read_user(e->sock, cnt, ptr) == 0)
                e->sock_len = cnt;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
