// SPDX-License-Identifier: GPL-2.0
// `ares mod fileless-exec` — userspace analyzer for the anonymous-
// executable-mapping signal. Owns the fileless_exec BPF skeleton lifecycle;
// the dispatcher in mod.c drives the poll loop and teardown order. Kernel
// side: src/modules/fileless_exec.bpf.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fileless_exec.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"

// ── per-pid tally (tallied unconditionally so summary survives -o) ─────────

#define FILELESS_STAT_MAX 64

typedef struct {
    __u32    pid;
    char     comm[TASK_COMM_LEN];
    uint32_t count;
} fileless_stat_t;

static fileless_stat_t fileless_stats[FILELESS_STAT_MAX];
static int              fileless_stat_count = 0;

static void fileless_stat_add(__u32 pid, const char *comm)
{
    for (int i = 0; i < fileless_stat_count; i++) {
        if (fileless_stats[i].pid == pid) {
            fileless_stats[i].count++;
            return;
        }
    }
    if (fileless_stat_count >= FILELESS_STAT_MAX) return;
    fileless_stats[fileless_stat_count].pid = pid;
    snprintf(fileless_stats[fileless_stat_count].comm, TASK_COMM_LEN, "%s", comm);
    fileless_stats[fileless_stat_count].count = 1;
    fileless_stat_count++;
}

static struct fileless_exec_bpf *g_skel = NULL;
static struct bpf_link          *fileless_ff = NULL;
static struct ring_buffer       *g_rb = NULL;
static struct bpf_link          *mmap_link = NULL;

// ---- ring-buffer callback ---------------------------------------------------

static int fileless_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_FILELESS_EXEC || sz < sizeof(struct fileless_exec_event))
        return 0;

    const struct fileless_exec_event *e = data;
    fileless_stat_add(e->h.pid, e->comm);

    if (!mc->quiet) {
        printf("[fileless-exec] PID:%-6d (%s) anonymous executable mmap, %llu bytes%s%s\n",
               e->h.pid, e->comm, (unsigned long long)e->size,
               e->anon_name[0] ? " tag=" : "", e->anon_name);
    }

    if (mc->sink != NULL) {
        mod_emit_fileless_exec(&mc->sink->jb, e);
        ares_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *fileless_setup(int uid, struct ares_mod_ctx *mc)
{
    g_skel = fileless_exec_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod fileless-exec: failed to open BPF skeleton\n");
        return NULL;
    }
    if (fileless_exec_bpf__load(g_skel)) {
        fprintf(stderr, "mod fileless-exec: failed to load BPF\n");
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

    mmap_link = bpf_program__attach(g_skel->progs.on_uprobe_mmap);
    if (!mmap_link) {
        fprintf(stderr, "mod fileless-exec: kprobe/uprobe_mmap unavailable, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        fileless_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!fileless_ff) fprintf(stderr, "mod fileless-exec: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            fileless_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod fileless-exec: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (fileless_ff) { bpf_link__destroy(fileless_ff); fileless_ff = NULL; }
    if (mmap_link)   { bpf_link__destroy(mmap_link);   mmap_link   = NULL; }
    if (g_skel)      { fileless_exec_bpf__destroy(g_skel); g_skel  = NULL; }
    return NULL;
}

static void fileless_teardown(void)
{
    if (fileless_ff) { bpf_link__destroy(fileless_ff); fileless_ff = NULL; }
    if (mmap_link)   { bpf_link__destroy(mmap_link);   mmap_link   = NULL; }
    if (g_rb)        { ring_buffer__free(g_rb);        g_rb        = NULL; }
    if (g_skel)      { fileless_exec_bpf__destroy(g_skel); g_skel  = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void fileless_print_summary(void)
{
    if (fileless_stat_count == 0) return;

    printf("[fileless-exec] --- Fileless Exec Summary ---------------------------\n");
    printf("[fileless-exec]   PID     Comm             Count\n");
    for (int i = 0; i < fileless_stat_count; i++) {
        printf("[fileless-exec]  %6u  %-16s  %6u\n",
               fileless_stats[i].pid, fileless_stats[i].comm, fileless_stats[i].count);
    }
    printf("[fileless-exec]  %d process%s triggered an anonymous-exec mapping\n",
           fileless_stat_count, fileless_stat_count == 1 ? "" : "es");
}

static void fileless_emit_summary(struct ares_sink *s)
{
    if (fileless_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"fileless_exec_summary\"");
    jb_s(j, ",\"process_count\":"); jb_u64(j, (unsigned long long)fileless_stat_count);
    jb_s(j, ",\"processes\":[");
    for (int i = 0; i < fileless_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");    jb_u64(j, fileless_stats[i].pid);
        jb_s(j, ",\"comm\":\""); jb_esc(j, fileless_stats[i].comm); jb_c(j, '"');
        jb_s(j, ",\"count\":");  jb_u64(j, fileless_stats[i].count);
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    ares_sink_emit(s);
}

static unsigned long long fileless_drops(void)
{
    return g_skel ? ares_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_fileless_exec = {
    .name          = "fileless-exec",
    .description   = "Detect anonymous executable memory mappings with no ART JIT "
                      "tag (fileless native code execution -- the mechanism behind "
                      "native packers/unpackers and multi-stage droppers that avoid "
                      "writing a payload to disk; stealthy -- kprobe only, zero "
                      "uprobes)",
    .setup         = fileless_setup,
    .teardown      = fileless_teardown,
    .print_summary = fileless_print_summary,
    .emit_summary  = fileless_emit_summary,
    .drops         = fileless_drops,
};
