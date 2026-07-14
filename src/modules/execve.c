// SPDX-License-Identifier: GPL-2.0
// `ares mod execve` — userspace analyzer for execve/execveat syscall events.
// Owns the execve BPF skeleton lifecycle; the dispatcher in mod.c drives
// the poll loop and teardown order. Kernel side: src/modules/execve.bpf.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execve.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/runtime.h"
#include "common/symbolize.h"
#include "common/human_out.h"      // SYM1 Phase 4c: shared stdout formatter
#include "modules/mod_events.h"
#include "modules/mod_emit.h"

// ── per-binary exec tally (tallied unconditionally so summary survives -o) ───

#define EXEC_STAT_MAX 256

typedef struct {
    char     path[128];   // sized to execve_event.filename
    uint32_t count;
} exec_stat_t;

static exec_stat_t exec_stats[EXEC_STAT_MAX];
static int         exec_stat_count = 0;

static void exec_stat_add(const char *path)
{
    for (int i = 0; i < exec_stat_count; i++) {
        if (strcmp(exec_stats[i].path, path) == 0) {
            exec_stats[i].count++;
            return;
        }
    }
    if (exec_stat_count >= EXEC_STAT_MAX) return;
    snprintf(exec_stats[exec_stat_count].path, sizeof(exec_stats[0].path), "%s", path);
    exec_stats[exec_stat_count].count = 1;
    exec_stat_count++;
}

static int exec_stat_cmp_desc(const void *a, const void *b)
{
    uint32_t ca = ((const exec_stat_t *)a)->count;
    uint32_t cb = ((const exec_stat_t *)b)->count;
    return (ca > cb) ? -1 : (ca < cb) ? 1 : 0;
}

// Basenames that indicate root-access or tamper-detection-relevant execution.
// Edit freely; NULL-terminated like rasp_props in prop_read.c.
static const char *const suspicious_bins[] = {
    "su", "magisk", "busybox", "mount", "sh", "bash",
    "getprop", "setprop", "setenforce", "getenforce",
    NULL,
};

static bool is_suspicious_bin(const char *path)
{
    // compare basename only
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (int i = 0; suspicious_bins[i]; i++)
        if (strcmp(suspicious_bins[i], base) == 0) return true;
    return false;
}

static struct execve_bpf *g_skel       = NULL;
static struct bpf_link   *ex_ff        = NULL;
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

    exec_stat_add(e->filename);

    if (!mc->quiet) {
        char argv_buf[MAX_ARGV_ENTRIES * (MAX_ARGV_STR + 4) + 4];
        int off = 0;
        off += snprintf(argv_buf + off, sizeof(argv_buf) - off, "[");
        for (__u32 j = 0; j < e->argc && j < MAX_ARGV_ENTRIES; j++) {
            if (j) off += snprintf(argv_buf + off, sizeof(argv_buf) - off, ", ");
            off += snprintf(argv_buf + off, sizeof(argv_buf) - off, "\"%s\"", e->argv[j]);
        }
        snprintf(argv_buf + off, sizeof(argv_buf) - off, "]");

        // SYM1 Phase 4c: was printf(...); the caller/frame lines already
        // hand-rolled human_out's "         [tag]   | " prefix (pre-dating
        // human_out.c) but with a stale "[event]" tag mismatched against this
        // file's own "[exec]" header -- now unified through human_detail with
        // the correct "exec" tag.
        ts_print("[exec]  > [EXEC]  PID:%d (%s) %s%s%s\n",
               e->h.pid, e->comm, e->filename,
               e->argc ? " " : "",
               e->argc ? argv_buf : "");

        if (e->stack_depth > 0) {
            __u32 start = 1;
            if (start < e->stack_depth && e->call_stack[start]) {
                char caller_sym[320];
                sym_resolve(hdr->pid, e->call_stack[start], caller_sym, sizeof(caller_sym));
                human_detail("exec", "caller: %s\n", caller_sym);
            }
            if (mc->verbose) {
                for (__u32 i = start + 1; i < e->stack_depth; i++) {
                    if (!e->call_stack[i]) break;
                    char frame_sym[320];
                    sym_resolve(hdr->pid, e->call_stack[i], frame_sym, sizeof(frame_sym));
                    human_detail("exec", "#%u %s\n", i, frame_sym);
                }
            }
        }
    }

    if (mc->sink != NULL) {
        char symbuf[STACK_DEPTH][320];
        const char *syms[STACK_DEPTH];
        for (int i = 0; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
            if (!e->call_stack[i]) { syms[i] = NULL; continue; }
            sym_resolve(hdr->pid, e->call_stack[i], symbuf[i], sizeof(symbuf[i]));
            syms[i] = symbuf[i];
        }
        mod_emit_execve(&mc->sink->jb, e, syms);
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

    __u8 one = 1;
    if (uid > 0) {
        __u32 u = (__u32)uid;
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_uids), &u, &one, BPF_ANY);
    }
    if (mc->tgt && mc->tgt->n > 0) {
        for (int i = 0; i < mc->tgt->n; i++) {
            __u32 tgid = (__u32)mc->tgt->pids[i];
            bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_pids), &tgid, &one, BPF_ANY);
        }
    }

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

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        ex_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!ex_ff) fprintf(stderr, "mod execve: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            ex_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod execve: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (ex_ff)         { bpf_link__destroy(ex_ff);         ex_ff         = NULL; }
    if (execve_link)   { bpf_link__destroy(execve_link);   execve_link   = NULL; }
    if (execveat_link) { bpf_link__destroy(execveat_link); execveat_link = NULL; }
    if (exec_link)     { bpf_link__destroy(exec_link);     exec_link     = NULL; }
    if (g_skel)        { execve_bpf__destroy(g_skel);      g_skel        = NULL; }
    return NULL;
}

static void ex_teardown(void)
{
    if (ex_ff)         { bpf_link__destroy(ex_ff);         ex_ff         = NULL; }
    if (execve_link)   { bpf_link__destroy(execve_link);   execve_link   = NULL; }
    if (execveat_link) { bpf_link__destroy(execveat_link); execveat_link = NULL; }
    if (exec_link)     { bpf_link__destroy(exec_link);     exec_link     = NULL; }
    if (g_rb)          { ring_buffer__free(g_rb);          g_rb          = NULL; }
    if (g_skel)        { execve_bpf__destroy(g_skel);      g_skel        = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void ex_print_summary(void)
{
    if (exec_stat_count == 0) return;

    qsort(exec_stats, exec_stat_count, sizeof(exec_stat_t), exec_stat_cmp_desc);

    uint64_t total = 0;
    int flagged = 0;
    for (int i = 0; i < exec_stat_count; i++) {
        total += exec_stats[i].count;
        if (is_suspicious_bin(exec_stats[i].path)) flagged++;
    }

    int use_color = isatty(STDOUT_FILENO);

#define EXEC_SEP "  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80" \
                 "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"    \
                 "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"    \
                 "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"    \
                 "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"    \
                 "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"    \
                 "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n"

    printf("[exec] \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Exec Summary "
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
           "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\n");
    printf("[exec]       Count  Binary\n");
    printf("[exec]" EXEC_SEP);

    for (int i = 0; i < exec_stat_count; i++) {
        bool sus = is_suspicious_bin(exec_stats[i].path);
        if (sus && use_color)
            printf("[exec]  \033[1;33m[!] %6u  %s\033[0m\n",
                   exec_stats[i].count, exec_stats[i].path);
        else if (sus)
            printf("[exec]  [!] %6u  %s\n",
                   exec_stats[i].count, exec_stats[i].path);
        else
            printf("[exec]      %6u  %s\n",
                   exec_stats[i].count, exec_stats[i].path);
    }

    printf("[exec]" EXEC_SEP);
    printf("[exec]  %llu exec%s across %d unique binar%s (%d flagged)\n",
           (unsigned long long)total, total == 1 ? "" : "s",
           exec_stat_count, exec_stat_count == 1 ? "y" : "ies",
           flagged);
}

// File twin of ex_print_summary: same tally, one {"type":"execve_summary",...}
// record so ares-mcp can consume the exec tally without re-deriving it from
// the per-event stream. Not sorted (print_summary's qsort already ran on
// exec_stats in-place by the time this is called).
static void ex_emit_summary(struct ares_sink *s)
{
    if (exec_stat_count == 0) return;

    uint64_t total = 0;
    int flagged = 0;
    for (int i = 0; i < exec_stat_count; i++) {
        total += exec_stats[i].count;
        if (is_suspicious_bin(exec_stats[i].path)) flagged++;
    }

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"execve_summary\"");
    jb_s(j, ",\"total_execs\":");    jb_u64(j, total);
    jb_s(j, ",\"unique_binaries\":"); jb_u64(j, (unsigned long long)exec_stat_count);
    jb_s(j, ",\"flagged\":");        jb_u64(j, (unsigned long long)flagged);
    jb_s(j, ",\"binaries\":[");
    for (int i = 0; i < exec_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"path\":\"");  jb_esc(j, exec_stats[i].path); jb_c(j, '"');
        jb_s(j, ",\"count\":");   jb_u64(j, exec_stats[i].count);
        jb_s(j, ",\"suspicious\":"); jb_s(j, is_suspicious_bin(exec_stats[i].path) ? "true" : "false");
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    ares_sink_emit(s);
}

static unsigned long long ex_drops(void)
{
    return g_skel ? ares_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_execve = {
    .name          = "execve",
    .description   = "Trace execve syscalls with full argv and call stack",
    .setup         = ex_setup,
    .teardown      = ex_teardown,
    .print_summary = ex_print_summary,
    .emit_summary  = ex_emit_summary,
    .drops         = ex_drops,
};
