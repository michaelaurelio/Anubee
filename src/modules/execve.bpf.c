// SPDX-License-Identifier: GPL-2.0
// BPF object for the execve analyzer: trace execve syscalls with full argv and call stack.
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
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

// Full execve tracing via kprobe on __arm64_sys_execve.
// __arm64_sys_execve(const struct pt_regs *regs): userspace syscall args in regs->regs[0..2].
// Falls back to on_proc_exec (sched_process_exec) when this kprobe fails to attach.
SEC("kprobe/__arm64_sys_execve")
int BPF_KPROBE(on_execve, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    struct execve_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        return 0;
    }

    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_EXECVE;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Strip top byte: Android heap tagging sets bits 56-63 on dynamic allocations.
    // bpf_probe_read_user calls access_ok() which rejects tagged addresses.
    unsigned long filename_ptr = BPF_CORE_READ(regs, regs[0]) & 0x00FFFFFFFFFFFFFFul;
    unsigned long argv_base    = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;

    bpf_probe_read_user_str(e->filename, sizeof(e->filename), (void *)filename_ptr);

    e->argc = 0;
    bool done = false;
    #pragma unroll
    for (int i = 0; i < MAX_ARGV_ENTRIES; i++) {
        e->argv[i][0] = '\0';
        if (done)
            continue;
        char *arg = NULL;
        unsigned long slot = argv_base + (unsigned long)i * sizeof(char *);
        if (bpf_probe_read_user(&arg, sizeof(arg), (void *)slot) < 0 || !arg) {
            done = true;
            continue;
        }
        // Strip tag from the individual string pointer too
        unsigned long arg_addr = (unsigned long)arg & 0x00FFFFFFFFFFFFFFul;
        bpf_probe_read_user_str(e->argv[i], MAX_ARGV_STR, (void *)arg_addr);
        e->argc++;
    }

    long sr = bpf_get_stack(ctx, e->call_stack, sizeof(e->call_stack), BPF_F_USER_STACK);
    e->stack_depth = (sr > 0) ? (__u32)((__u64)sr >> 3) : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// execveat(dirfd, pathname, argv, envp, flags): filename in regs[1], argv in regs[2].
SEC("kprobe/__arm64_sys_execveat")
int BPF_KPROBE(on_execveat, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    struct execve_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        return 0;
    }

    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_EXECVE;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    unsigned long filename_ptr = BPF_CORE_READ(regs, regs[1]) & 0x00FFFFFFFFFFFFFFul;
    unsigned long argv_base    = BPF_CORE_READ(regs, regs[2]) & 0x00FFFFFFFFFFFFFFul;

    bpf_probe_read_user_str(e->filename, sizeof(e->filename), (void *)filename_ptr);

    e->argc = 0;
    bool done = false;
    #pragma unroll
    for (int i = 0; i < MAX_ARGV_ENTRIES; i++) {
        e->argv[i][0] = '\0';
        if (done)
            continue;
        char *arg = NULL;
        unsigned long slot = argv_base + (unsigned long)i * sizeof(char *);
        if (bpf_probe_read_user(&arg, sizeof(arg), (void *)slot) < 0 || !arg) {
            done = true;
            continue;
        }
        unsigned long arg_addr = (unsigned long)arg & 0x00FFFFFFFFFFFFFFul;
        bpf_probe_read_user_str(e->argv[i], MAX_ARGV_STR, (void *)arg_addr);
        e->argc++;
    }

    long sr = bpf_get_stack(ctx, e->call_stack, sizeof(e->call_stack), BPF_F_USER_STACK);
    e->stack_depth = (sr > 0) ? (__u32)((__u64)sr >> 3) : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Fallback when sys_enter_execve is unavailable: fires after exec replaces process image.
// Provides filename only — no argv, no pre-exec call stack.
SEC("tp/sched/sched_process_exec")
int on_proc_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    struct execve_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        return 0;
    }

    __u64 id  = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_EXECVE;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->argc       = 0;
    e->stack_depth = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // __data_loc_filename: lower 16 bits = byte offset from start of ctx
    __u16 off = (__u16)(ctx->__data_loc_filename & 0xffff);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (char *)ctx + off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
