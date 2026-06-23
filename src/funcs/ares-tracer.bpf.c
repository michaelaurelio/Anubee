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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

static __always_inline void bump_dropped(void)
{
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&dropped, &k);
    if (c) __sync_fetch_and_add(c, 1);
}

// Per-tid span stack (shared with the correlate engine; see header).
#include "common/span_stack.bpf.h"


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
        bump_dropped();
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
        bump_dropped();
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