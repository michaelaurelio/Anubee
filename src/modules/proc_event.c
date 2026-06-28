// SPDX-License-Identifier: GPL-2.0
// `ares mod proc-event` — userspace analyzer for process fork and exit events.
// Owns the proc_event BPF skeleton lifecycle; the dispatcher in mod.c drives
// the poll loop and teardown order. Kernel side: src/modules/proc_event.bpf.c.
#include <stdio.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "proc_event.skel.h"
#include "common/analyzer.h"
#include "common/emit.h"
#include "common/symbolize.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"

static struct proc_event_bpf *g_skel = NULL;
static struct ring_buffer     *g_rb   = NULL;

// ── event counters (tallied unconditionally so summary survives -o / quiet) ──

static unsigned long g_forks    = 0;
static unsigned long g_exits    = 0;
static unsigned long g_sig_exits = 0;

// ---- ring-buffer callback ---------------------------------------------------

static int pe_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    switch (hdr->type) {
    case MOD_EV_SPAWN: {
        if (sz < sizeof(struct spawn_event))
            return 0;
        const struct spawn_event *e = data;
        g_forks++;
        if (!mc->quiet)
            printf("[proc]  > [FORK]  PID:%u (%s) -> child PID:%u\n",
                   e->h.pid, e->comm, e->child_pid);
        if (mc->sink != NULL) {
            mod_emit_spawn(&mc->sink->jb, e);
            ares_sink_emit(mc->sink);
        }
        break;
    }
    case MOD_EV_PROC_EXIT: {
        if (sz < sizeof(struct proc_exit_event))
            return 0;
        const struct proc_exit_event *e = data;
        int sig    = e->exit_code & 0x7f;
        int status = (e->exit_code >> 8) & 0xff;
        g_exits++;
        if (sig) g_sig_exits++;
        if (!mc->quiet) {
            if (sig)
                printf("[proc]  > [EXIT]  PID:%u (%s) killed by signal %d\n",
                       e->h.pid, e->comm, sig);
            else
                printf("[proc]  > [EXIT]  PID:%u (%s) exit status %d\n",
                       e->h.pid, e->comm, status);
        }
        if (mc->sink != NULL) {
            mod_emit_proc_exit(&mc->sink->jb, e);
            ares_sink_emit(mc->sink);
        }
        sym_flush_pid((int)e->h.pid);
        break;
    }
    default:
        return 0;
    }
    return 0;
}

// ---- summary ----------------------------------------------------------------

static void pe_print_summary(void)
{
    if (g_forks == 0 && g_exits == 0) return;
    printf("[proc] \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Process Event Summary "
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n");
    printf("[proc]  %lu fork%s, %lu exit%s (%lu by signal)\n",
           g_forks,    g_forks    == 1 ? "" : "s",
           g_exits,    g_exits    == 1 ? "" : "s",
           g_sig_exits);
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *pe_setup(int uid, struct ares_mod_ctx *mc)
{
    g_skel = proc_event_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod proc-event: failed to open BPF skeleton\n");
        return NULL;
    }
    if (proc_event_bpf__load(g_skel)) {
        fprintf(stderr, "mod proc-event: failed to load BPF\n");
        goto err;
    }
    __u32 u = (__u32)uid; __u8 one = 1;
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_uids), &u, &one, BPF_ANY);
    if (proc_event_bpf__attach(g_skel)) {
        fprintf(stderr, "mod proc-event: failed to attach\n");
        goto err;
    }
    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            pe_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod proc-event: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    proc_event_bpf__destroy(g_skel);
    g_skel = NULL;
    return NULL;
}

static void pe_teardown(void)
{
    if (g_rb)   { ring_buffer__free(g_rb);             g_rb   = NULL; }
    if (g_skel) { proc_event_bpf__destroy(g_skel);     g_skel = NULL; }
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_proc_event = {
    .name          = "proc-event",
    .description   = "Trace process fork and exit events (stealthy — kernel tracepoints, zero uprobes)",
    .setup         = pe_setup,
    .teardown      = pe_teardown,
    .print_summary = pe_print_summary,
};
