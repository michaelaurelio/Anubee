// SPDX-License-Identifier: GPL-2.0
//
// Per-tid span stack — shared BPF *source* for the funcs and (future) correlate
// engines. This is NOT a runtime-shared map: each BPF object that #includes this
// header gets its own map instances at load time, so the detectability firewall
// (quiet kprobe objects vs. the loud uprobe object) is unaffected — only the code
// is shared.
//
// The includer must, before #include, provide:
//   - vmlinux.h and <bpf/bpf_helpers.h>  (types __u32/__u64, bpf_map_* helpers)
//   - NUM_ARGS                            (entry-arg slots saved per frame)
#ifndef __ARES_SPAN_STACK_BPF_H
#define __ARES_SPAN_STACK_BPF_H

#define MAX_SPAN_DEPTH 32   // bounded per-thread instrumented-call nesting

// One instrumented stack frame. The per-tid stack of these replaces the old
// single-slot entry_ctx, so nested/recursive probed calls on one thread no
// longer clobber each other's entry context.
struct span_frame {
    __u64 entry_addr;              // function entry IP (for the RETURN event)
    __u64 entry_sp;               // user SP at entry (for SP-based reconciliation)
    __u64 timestamp;              // entry ktime (for elapsed_ns)
    __u64 args[NUM_ARGS];          // saved entry args, replayed into the RETURN event
};

// Per-thread depth of the span stack. Keyed by TID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);            // TID
    __type(value, __u32);          // current stack depth
} span_depth SEC(".maps");

// Per-thread span frames, keyed by {TID, slot}; slot in [0, MAX_SPAN_DEPTH).
struct frame_key {
    __u32 tid;
    __u32 slot;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024 * MAX_SPAN_DEPTH);
    __type(key, struct frame_key);
    __type(value, struct span_frame);
} span_frames SEC(".maps");

// Write back a new stack depth, deleting the per-tid entry when it reaches 0 so
// only threads currently inside a probe occupy span_depth (matches the old
// entry_map lifecycle and bounds map pressure on many-threaded targets).
static __always_inline void span_depth_set(__u32 tid, __u32 depth)
{
    if (depth == 0)
        bpf_map_delete_elem(&span_depth, &tid);
    else
        bpf_map_update_elem(&span_depth, &tid, &depth, BPF_ANY);
}

// Drop frames whose function has already returned (user SP risen above the
// frame's entry SP). Keeps the stack honest when a uretprobe was missed
// (longjmp / exception / noreturn). aarch64 stack grows down: inside a frame
// current_sp <= entry_sp; after the frame returns current_sp > entry_sp.
static __always_inline void span_stack_reconcile(__u32 tid, __u64 cur_sp)
{
    #pragma unroll
    for (int i = 0; i < MAX_SPAN_DEPTH; i++) {
        __u32 *dp = bpf_map_lookup_elem(&span_depth, &tid);
        if (!dp || *dp == 0)
            break;
        __u32 top = *dp - 1;
        struct frame_key k = { .tid = tid, .slot = top };
        struct span_frame *f = bpf_map_lookup_elem(&span_frames, &k);
        if (!f)
            break;
        if (cur_sp <= f->entry_sp)
            break;                 // frame still live
        bpf_map_delete_elem(&span_frames, &k);
        span_depth_set(tid, top);  // shrink depth (delete at 0)
    }
}

// Push an entry frame for the current thread (no-op past MAX_SPAN_DEPTH).
static __always_inline void span_stack_push(__u32 tid, __u64 entry_addr,
                                            __u64 entry_sp, __u64 ts,
                                            const long raw[NUM_ARGS])
{
    __u32 *dp = bpf_map_lookup_elem(&span_depth, &tid);
    __u32 d = dp ? *dp : 0;
    // Depth cap: beyond MAX_SPAN_DEPTH nested instrumented frames we stop
    // tracking. Those frames' returns may mis-attribute until the stack unwinds
    // back under the cap — only deep recursion of a probed function hits this.
    if (d >= MAX_SPAN_DEPTH)
        return;
    struct frame_key k = { .tid = tid, .slot = d };
    struct span_frame f = {};
    f.entry_addr = entry_addr;
    f.entry_sp   = entry_sp;
    f.timestamp  = ts;
    #pragma unroll
    for (int i = 0; i < NUM_ARGS; i++)
        f.args[i] = (unsigned long)raw[i];
    bpf_map_update_elem(&span_frames, &k, &f, BPF_ANY);
    __u32 nd = d + 1;
    bpf_map_update_elem(&span_depth, &tid, &nd, BPF_ANY);
}

// Pop the top frame (used to undo a push when a ringbuf reserve fails).
static __always_inline void span_stack_pop(__u32 tid)
{
    __u32 *dp = bpf_map_lookup_elem(&span_depth, &tid);
    if (!dp || *dp == 0)
        return;
    __u32 top = *dp - 1;
    struct frame_key k = { .tid = tid, .slot = top };
    bpf_map_delete_elem(&span_frames, &k);
    span_depth_set(tid, top);
}

// Delete an entire thread's stack (called on thread exit).
static __always_inline void span_stack_clear(__u32 tid)
{
    #pragma unroll
    for (int s = 0; s < MAX_SPAN_DEPTH; s++) {
        struct frame_key k = { .tid = tid, .slot = (__u32)s };
        bpf_map_delete_elem(&span_frames, &k);
    }
    bpf_map_delete_elem(&span_depth, &tid);
}

#endif /* __ARES_SPAN_STACK_BPF_H */
