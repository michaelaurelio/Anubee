// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>
#include "module.h"
#include "ares-tracer-priv.h"

static struct bpf_link *execve_link   = NULL;
static struct bpf_link *execveat_link = NULL;
static struct bpf_link *exec_link     = NULL;

static void ex_pre_attach(struct ares_tracer_bpf *skel)
{
    bpf_program__set_autoattach(skel->progs.on_execve,    false);
    bpf_program__set_autoattach(skel->progs.on_execveat,  false);
    bpf_program__set_autoattach(skel->progs.on_proc_exec, false);
}

static int ex_attach(struct ares_tracer_bpf *skel)
{
    execve_link   = bpf_program__attach(skel->progs.on_execve);
    execveat_link = bpf_program__attach(skel->progs.on_execveat);

    if (!execve_link)
        err_print("   [bpf] > kprobe/__arm64_sys_execve unavailable\n");
    if (!execveat_link)
        err_print("   [bpf] > kprobe/__arm64_sys_execveat unavailable\n");

    if (!execve_link && !execveat_link) {
        err_print("   [bpf] > both kprobes unavailable, falling back to sched_process_exec (filename only)\n");
        exec_link = bpf_program__attach(skel->progs.on_proc_exec);
        if (!exec_link) {
            err_print("   [bpf] > sched_process_exec also unavailable; execve tracing disabled\n");
            return -2;
        }
    }

    ts_print("[proc]  > execve tracing enabled%s\n",
             (execve_link || execveat_link) ? "" : " (fallback: filename only)");
    return 0;
}

static void ex_detach(void)
{
    if (execve_link)   { bpf_link__destroy(execve_link);   execve_link   = NULL; }
    if (execveat_link) { bpf_link__destroy(execveat_link); execveat_link = NULL; }
    if (exec_link)     { bpf_link__destroy(exec_link);     exec_link     = NULL; }
}

static int ex_handle_event(const struct trace_event_header *hdr, const void *data, size_t sz)
{
    if (hdr->type != ARES_EVENT_EXECVE)
        return -1;
    const struct execve_event *e = data;
    if (sz < sizeof(*e)) return 0;

    char argv_buf[MAX_ARGV_ENTRIES * (MAX_ARGV_STR + 4) + 4];
    int off = 0;
    off += snprintf(argv_buf + off, sizeof(argv_buf) - off, "[");
    for (__u32 j = 0; j < e->argc && j < MAX_ARGV_ENTRIES; j++) {
        if (j) off += snprintf(argv_buf + off, sizeof(argv_buf) - off, ", ");
        off += snprintf(argv_buf + off, sizeof(argv_buf) - off, "\"%s\"", e->argv[j]);
    }
    snprintf(argv_buf + off, sizeof(argv_buf) - off, "]");

    ts_print("[proc]  > [EXEC]  PID:%d (%s) %s%s%s\n",
        e->h.pid, e->comm, e->filename,
        e->argc ? " " : "",
        e->argc ? argv_buf : "");

    if (e->stack_depth > 0) {
        char caller_mod[128] = "";
        unsigned long caller_off = 0;
        __u32 start = (e->stack_depth > 0) ? 1 : 0;
        if (start < e->stack_depth && e->call_stack[start]) {
            if (lookup_caller(hdr->pid, e->call_stack[start],
                              caller_mod, sizeof(caller_mod), &caller_off) == 0)
                out_print("         [event]   | caller: %s+0x%lx\n",
                          caller_mod, caller_off);
        }
        if (!caller_only) {
            for (__u32 i = start + 1; i < e->stack_depth; i++) {
                if (!e->call_stack[i]) break;
                char frame_mod[128] = "";
                unsigned long frame_off = 0;
                if (lookup_caller(hdr->pid, e->call_stack[i],
                                  frame_mod, sizeof(frame_mod), &frame_off) == 0)
                    out_print("         [event]   | #%u %s+0x%lx\n",
                              i, frame_mod, frame_off);
                else
                    out_print("         [event]   | #%u 0x%llx\n",
                              i, (unsigned long long)e->call_stack[i]);
            }
        }
    }
    return 0;
}

ares_module_t module_execve = {
    .name         = "execve",
    .description  = "Trace execve syscalls with full argv and call stack",
    .pre_attach   = ex_pre_attach,
    .attach       = ex_attach,
    .detach       = ex_detach,
    .handle_event = ex_handle_event,
};
