// SPDX-License-Identifier: GPL-2.0
// `ares mod execve` — userspace analyzer for execve/execveat syscall events.
// Owns the execve BPF skeleton lifecycle; the dispatcher in mod.c drives
// the poll loop and teardown order. Kernel side: src/modules/execve.bpf.c.
#include <stdio.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execve.skel.h"
#include "common/analyzer.h"
#include "common/emit.h"
#include "common/symbolize.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"

static struct execve_bpf *g_skel       = NULL;
static struct ring_buffer *g_rb        = NULL;
static struct bpf_link    *execve_link   = NULL;
static struct bpf_link    *execveat_link = NULL;
static struct bpf_link    *exec_link     = NULL;

// ---- ring-buffer callback ---------------------------------------------------

static int ex_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_EXECVE || sz < sizeof(struct execve_event))
        return 0;

    const struct execve_event *e = data;

    if (!mc->quiet) {
        char argv_buf[MAX_ARGV_ENTRIES * (MAX_ARGV_STR + 4) + 4];
        int off = 0;
        off += snprintf(argv_buf + off, sizeof(argv_buf) - off, "[");
        for (__u32 j = 0; j < e->argc && j < MAX_ARGV_ENTRIES; j++) {
            if (j) off += snprintf(argv_buf + off, sizeof(argv_buf) - off, ", ");
            off += snprintf(argv_buf + off, sizeof(argv_buf) - off, "\"%s\"", e->argv[j]);
        }
        snprintf(argv_buf + off, sizeof(argv_buf) - off, "]");

        printf("[exec]  > [EXEC]  PID:%d (%s) %s%s%s\n",
               e->h.pid, e->comm, e->filename,
               e->argc ? " " : "",
               e->argc ? argv_buf : "");

        if (e->stack_depth > 0) {
            __u32 start = 1;
            if (start < e->stack_depth && e->call_stack[start]) {
                char caller_sym[320];
                sym_resolve(hdr->pid, e->call_stack[start], caller_sym, sizeof(caller_sym));
                printf("         [event]   | caller: %s\n", caller_sym);
            }
            if (mc->verbose) {
                for (__u32 i = start + 1; i < e->stack_depth; i++) {
                    if (!e->call_stack[i]) break;
                    char frame_sym[320];
                    sym_resolve(hdr->pid, e->call_stack[i], frame_sym, sizeof(frame_sym));
                    printf("         [event]   | #%u %s\n", i, frame_sym);
                }
            }
        }
    }

    if (mc->sink != NULL) {
        mod_emit_execve(&mc->sink->jb, e);
        ares_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *ex_setup(int uid, struct ares_mod_ctx *mc)
{
    g_skel = execve_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod execve: failed to open BPF skeleton\n");
        return NULL;
    }
    if (execve_bpf__load(g_skel)) {
        fprintf(stderr, "mod execve: failed to load BPF\n");
        goto err;
    }

    __u32 u = (__u32)uid; __u8 one = 1;
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_uids), &u, &one, BPF_ANY);

    execve_link   = bpf_program__attach(g_skel->progs.on_execve);
    execveat_link = bpf_program__attach(g_skel->progs.on_execveat);

    if (!execve_link)
        fprintf(stderr, "mod execve: kprobe/__arm64_sys_execve unavailable\n");
    if (!execveat_link)
        fprintf(stderr, "mod execve: kprobe/__arm64_sys_execveat unavailable\n");

    if (!execve_link && !execveat_link) {
        fprintf(stderr, "mod execve: both kprobes unavailable, falling back to sched_process_exec (filename only)\n");
        exec_link = bpf_program__attach(g_skel->progs.on_proc_exec);
        if (!exec_link) {
            fprintf(stderr, "mod execve: sched_process_exec also unavailable; execve tracing disabled\n");
            goto err;
        }
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            ex_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod execve: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (execve_link)   { bpf_link__destroy(execve_link);   execve_link   = NULL; }
    if (execveat_link) { bpf_link__destroy(execveat_link); execveat_link = NULL; }
    if (exec_link)     { bpf_link__destroy(exec_link);     exec_link     = NULL; }
    if (g_skel)        { execve_bpf__destroy(g_skel);      g_skel        = NULL; }
    return NULL;
}

static void ex_teardown(void)
{
    if (execve_link)   { bpf_link__destroy(execve_link);   execve_link   = NULL; }
    if (execveat_link) { bpf_link__destroy(execveat_link); execveat_link = NULL; }
    if (exec_link)     { bpf_link__destroy(exec_link);     exec_link     = NULL; }
    if (g_rb)          { ring_buffer__free(g_rb);          g_rb          = NULL; }
    if (g_skel)        { execve_bpf__destroy(g_skel);      g_skel        = NULL; }
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_execve = {
    .name          = "execve",
    .description   = "Trace execve syscalls with full argv and call stack (stealthy — kprobes, zero uprobes)",
    .setup         = ex_setup,
    .teardown      = ex_teardown,
    .print_summary = NULL,
};
