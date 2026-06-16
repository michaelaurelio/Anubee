// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ares-tracer.h"
#include "common/lib_trace.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} target_uids SEC(".maps");

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


// Determine if a value is a user-space pointer (heuristic)
static __always_inline bool is_user_ptr(unsigned long val)
{
    unsigned long untagged = val & 0x00FFFFFFFFFFFFFFUL;
    return untagged > 0x10000UL && untagged < 0x800000000000UL;
}

static __always_inline int uid_matches(void)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    return bpf_map_lookup_elem(&target_uids, &uid) != NULL;
}


// Function entry handler to attach uprobe
SEC("uprobe")
int BPF_KPROBE(uprobe_open, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
    if (!uid_matches())
        return 0;

    struct task_struct *task;
    struct event *e;

    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = (__u32)(id >> 32);
    pid_t tid = (__u32)id;

    long raw[NUM_ARGS] = {a1, a2, a3, a4, a5, a6, a7, a8};

    // Reconcile any frames left by missed returns, then push this frame before
    // the ringbuf reserve so the uretprobe always has its entry context.
    __u64 entry_sp = (__u64)PT_REGS_SP(ctx);
    span_stack_reconcile(tid, entry_sp);
    span_stack_push(tid, (__u64)PT_REGS_IP(ctx), entry_sp,
                    bpf_ktime_get_ns(), raw);

    // Reserve space in ring buffer for event
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        span_stack_pop(tid);       // undo the push (matches old delete-on-fail)
        return 0;
    }

    // Fill event data
    task = (struct task_struct *)bpf_get_current_task();

    e->h.type = ARES_EVENT_CALL;
    e->h.pid = pid;
    e->h.tid = tid;
	e->h._pad = 0;
    e->entry_addr  = (__u64)PT_REGS_IP(ctx);
    e->caller_addr = (__u64)ctx->regs[30];
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->exit_event = false;

    #pragma unroll
    for (int i = 0; i < NUM_ARGS; i++) {
        e->args[i] = (unsigned long)raw[i];
        e->is_str[i] = 0;
        if (is_user_ptr((unsigned long)raw[i])) {
            unsigned long ptr = (unsigned long)raw[i] & 0x00FFFFFFFFFFFFFFul;
            long n = bpf_probe_read_user_str(e->strings[i], MAX_STR_LEN, (void *)ptr);
            if (n > 1)
                e->is_str[i] = 1;
        }
    }

    long stack_ret = bpf_get_stack(ctx, e->call_stack, sizeof(e->call_stack), BPF_F_USER_STACK);
    e->stack_depth = (stack_ret > 0) ? (__u32)((__u64)stack_ret >> 3) : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// Silent entry saver for -r (return-only) probes -> records entry context without emitting CALL event
SEC("uprobe")
int BPF_KPROBE(uprobe_save_only, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
    if (!uid_matches())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    pid_t tid = (__u32)id;

    long raw[NUM_ARGS] = {a1, a2, a3, a4, a5, a6, a7, a8};
    __u64 entry_sp = (__u64)PT_REGS_SP(ctx);
    span_stack_reconcile(tid, entry_sp);
    span_stack_push(tid, (__u64)PT_REGS_IP(ctx), entry_sp,
                    bpf_ktime_get_ns(), raw);
    return 0;
}


// Return handler for both paired probes (spec with '>') and return-only probes (-r flag).
SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_open)
{
    if (!uid_matches())
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = (__u32)(id >> 32);
    pid_t tid = (__u32)id;
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

    struct event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&span_frames, &fk);
        span_depth_set(tid, top);
        return 0;
    }

    e->h.type     = ARES_EVENT_RETURN;
    e->h.pid      = pid;
    e->h.tid      = tid;
    e->h._pad     = 0;
    e->entry_addr = saved->entry_addr;
    e->caller_addr = 0;
    e->elapsed_ns = now - saved->timestamp;
    e->ppid       = 0;
    e->args[0]    = 0;
    e->exit_event = true;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->retval    = (unsigned long)PT_REGS_RC(ctx);
    e->is_str[0] = 0;
    if (is_user_ptr(e->retval)) {
        unsigned long retptr = e->retval & 0x00FFFFFFFFFFFFFFul;
        long n = bpf_probe_read_user_str(e->strings[0], MAX_STR_LEN, (void *)retptr);
        if (n > 1) e->is_str[0] = 1;
    }

    #pragma unroll
    for (int i = 0; i < NUM_ARGS - 1; i++) {
        e->args[i + 1]    = saved->args[i];
        e->is_str[i + 1]  = 0;
        if (is_user_ptr(saved->args[i])) {
            unsigned long argptr = saved->args[i] & 0x00FFFFFFFFFFFFFFul;
            long n = bpf_probe_read_user_str(e->strings[i + 1], MAX_STR_LEN, (void *)argptr);
            if (n > 1) e->is_str[i + 1] = 1;
        }
    }

    long stack_ret = bpf_get_stack(ctx, e->call_stack, sizeof(e->call_stack), BPF_F_USER_STACK);
    e->stack_depth = (stack_ret > 0) ? (__u32)((__u64)stack_ret >> 3) : 0;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&span_frames, &fk);
    span_depth_set(tid, top);      // pop the frame we just consumed
    return 0;
}


// Shared mmap/munmap capture (emits lib_map_event / lib_unmap_event into events_rb).
#define LIBTRACE_EVENTS_RB events_rb
#include "common/lib_trace.bpf.h"

#include "modules/prop_read.bpf.c"
#include "modules/proc_event.bpf.c"
#include "modules/execve.bpf.c"