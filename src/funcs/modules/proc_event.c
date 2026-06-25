// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>
#include "module.h"
#include "ares-tracer-priv.h"

static struct bpf_link *fork_link = NULL;
static struct bpf_link *exit_link = NULL;

static void pe_pre_attach(struct ares_tracer_bpf *skel)
{
    bpf_program__set_autoattach(skel->progs.on_proc_fork, false);
    bpf_program__set_autoattach(skel->progs.on_proc_exit, false);
}

static int pe_attach(struct ares_tracer_bpf *skel)
{
    fork_link = bpf_program__attach(skel->progs.on_proc_fork);
    if (!fork_link) {
        err_print("   [bpf] > failed to attach sched_process_fork tracepoint\n");
        return -1;
    }
    exit_link = bpf_program__attach(skel->progs.on_proc_exit);
    if (!exit_link) {
        err_print("   [bpf] > failed to attach sched_process_exit tracepoint\n");
        return -1;
    }
    ts_print("[proc]  > process fork/exit tracing enabled\n");
    return 0;
}

static void pe_detach(void)
{
    if (fork_link) { bpf_link__destroy(fork_link); fork_link = NULL; }
    if (exit_link) { bpf_link__destroy(exit_link); exit_link = NULL; }
}

static int pe_handle_event(const struct trace_event_header *hdr, const void *data, size_t sz)
{
    if (hdr->type == ARES_EVENT_SPAWN) {
        const struct spawn_event *e = data;
        if (sz < sizeof(*e)) return 0;
        ts_print("[proc]  > [FORK]  PID:%d (%s) -> child PID:%d\n",
            e->h.pid, e->comm, e->child_pid);
        return 0;
    }
    if (hdr->type == ARES_EVENT_PROC_EXIT) {
        const struct proc_exit_event *e = data;
        if (sz < sizeof(*e)) return 0;
        int sig    = e->exit_code & 0x7f;
        int status = (e->exit_code >> 8) & 0xff;
        if (sig)
            ts_print("[proc]  > [EXIT]  PID:%d (%s) killed by signal %d\n",
                hdr->pid, e->comm, sig);
        else
            ts_print("[proc]  > [EXIT]  PID:%d (%s) exit status %d\n",
                hdr->pid, e->comm, status);
        // Flush the dead pid's cached maps so a recycled pid doesn't read stale symbols.
        // ponytail: route through the worker queue if in-flight frames for the dying pid matter.
        sym_flush_pid(hdr->pid);
        return 0;
    }
    return -1;
}

ares_module_t module_proc_event = {
    .name         = "proc-event",
    .description  = "Trace process fork and exit events",
    .pre_attach   = pe_pre_attach,
    .attach       = pe_attach,
    .detach       = pe_detach,
    .handle_event = pe_handle_event,
};
