// SPDX-License-Identifier: GPL-2.0
// `ares mod ransomware-burst` — userspace analyzer for the rename/unlink
// burst signal. Owns the ransomware_burst BPF skeleton lifecycle; the
// dispatcher in mod.c drives the poll loop and teardown order. Kernel side:
// src/modules/ransomware_burst.bpf.c. Classification:
// src/modules/ransomware_burst_classify.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ransomware_burst.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/launch.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/ransomware_burst_classify.h"

// ── per-pid tally (tallied unconditionally so summary survives -o) ─────────

#define RB_STAT_MAX 64

typedef struct {
    __u32    pid;
    char     comm[TASK_COMM_LEN];
    uint32_t burst_count;
    uint32_t max_touch_count;
    int      max_distinct;
} rb_stat_t;

static rb_stat_t rb_stats[RB_STAT_MAX];
static int       rb_stat_count = 0;

static void rb_stat_add(__u32 pid, const char *comm, int touch_count, int distinct)
{
    for (int i = 0; i < rb_stat_count; i++) {
        if (rb_stats[i].pid == pid) {
            rb_stats[i].burst_count++;
            if ((uint32_t)touch_count > rb_stats[i].max_touch_count)
                rb_stats[i].max_touch_count = (uint32_t)touch_count;
            if (distinct > rb_stats[i].max_distinct)
                rb_stats[i].max_distinct = distinct;
            return;
        }
    }
    if (rb_stat_count >= RB_STAT_MAX) return;
    rb_stats[rb_stat_count].pid = pid;
    strncpy(rb_stats[rb_stat_count].comm, comm, TASK_COMM_LEN - 1);
    rb_stats[rb_stat_count].comm[TASK_COMM_LEN - 1] = '\0';
    rb_stats[rb_stat_count].burst_count = 1;
    rb_stats[rb_stat_count].max_touch_count = (uint32_t)touch_count;
    rb_stats[rb_stat_count].max_distinct = distinct;
    rb_stat_count++;
}

// ── MANAGE_EXTERNAL_STORAGE grant check (one-time, at setup) ────────────────

// Tri-state: 1 = granted, 0 = checked and not granted, -1 = unknown (pkg
// unresolved, never checked).
static int g_manage_ext_storage = -1;

static void rb_check_manage_ext_storage(const char *pkg)
{
    if (!pkg) return;
    char cmd[320], out[256];
    snprintf(cmd, sizeof(cmd), "appops get %s MANAGE_EXTERNAL_STORAGE", pkg);
    if (ares_sh_exec(cmd, out, sizeof(out)) < 0) return;
    if (strstr(out, "allow"))
        g_manage_ext_storage = 1;
    else if (strstr(out, "deny") || strstr(out, "ignore") || strstr(out, "default"))
        g_manage_ext_storage = 0;
}

// Single short tag for the console line.
static const char *burst_tag(unsigned categories)
{
    if ((categories & RB_BURST_DETECTED) && (categories & RB_MANAGE_EXT_STORAGE))
        return "[burst+manage-ext-storage]";
    if (categories & RB_BURST_DETECTED)
        return "[burst]";
    return "[low-confidence]";
}

static struct ransomware_burst_bpf *g_skel        = NULL;
static struct bpf_link             *rb_ff         = NULL;
static struct ring_buffer          *g_rb          = NULL;
static struct bpf_link             *renameat_link  = NULL;
static struct bpf_link             *renameat2_link = NULL;
static struct bpf_link             *unlinkat_link  = NULL;

// ---- ring-buffer callback ---------------------------------------------------

static int rb_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_RANSOMWARE_BURST || sz < sizeof(struct ransomware_burst_event))
        return 0;

    const struct ransomware_burst_event *e = data;
    int distinct = burst_distinct_count(e->path_hashes, (int)e->touch_count);
    unsigned categories = classify_burst((int)e->touch_count, distinct, g_manage_ext_storage);
    rb_stat_add(e->h.pid, e->comm, (int)e->touch_count, distinct);

    if (!mc->quiet) {
        printf("[burst] %-26s PID:%-6d (%s) %u touches, %d distinct, %ums window, e.g. %s\n",
               burst_tag(categories), e->h.pid, e->comm, e->touch_count, distinct,
               e->window_ms, e->sample_path);
    }

    if (mc->sink != NULL) {
        mod_emit_ransomware_burst(&mc->sink->jb, e, distinct, g_manage_ext_storage);
        ares_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *rb_setup(int uid, struct ares_mod_ctx *mc)
{
    rb_check_manage_ext_storage(mc->pkg);
    if (g_manage_ext_storage == 1)
        printf("[burst] target holds MANAGE_EXTERNAL_STORAGE (All files access)\n");

    g_skel = ransomware_burst_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod ransomware-burst: failed to open BPF skeleton\n");
        return NULL;
    }
    if (ransomware_burst_bpf__load(g_skel)) {
        fprintf(stderr, "mod ransomware-burst: failed to load BPF\n");
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

    renameat_link  = bpf_program__attach(g_skel->progs.on_renameat);
    renameat2_link = bpf_program__attach(g_skel->progs.on_renameat2);
    unlinkat_link  = bpf_program__attach(g_skel->progs.on_unlinkat);

    if (!renameat_link)
        fprintf(stderr, "mod ransomware-burst: kprobe/__arm64_sys_renameat unavailable\n");
    if (!renameat2_link)
        fprintf(stderr, "mod ransomware-burst: kprobe/__arm64_sys_renameat2 unavailable (non-fatal)\n");
    if (!unlinkat_link)
        fprintf(stderr, "mod ransomware-burst: kprobe/__arm64_sys_unlinkat unavailable\n");

    if (!renameat_link && !renameat2_link && !unlinkat_link) {
        fprintf(stderr, "mod ransomware-burst: no rename/unlink kprobe attached, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        rb_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!rb_ff) fprintf(stderr, "mod ransomware-burst: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            rb_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod ransomware-burst: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (rb_ff)          { bpf_link__destroy(rb_ff);          rb_ff          = NULL; }
    if (renameat_link)  { bpf_link__destroy(renameat_link);  renameat_link  = NULL; }
    if (renameat2_link) { bpf_link__destroy(renameat2_link); renameat2_link = NULL; }
    if (unlinkat_link)  { bpf_link__destroy(unlinkat_link);  unlinkat_link  = NULL; }
    if (g_skel)         { ransomware_burst_bpf__destroy(g_skel); g_skel     = NULL; }
    return NULL;
}

static void rb_teardown(void)
{
    if (rb_ff)          { bpf_link__destroy(rb_ff);          rb_ff          = NULL; }
    if (renameat_link)  { bpf_link__destroy(renameat_link);  renameat_link  = NULL; }
    if (renameat2_link) { bpf_link__destroy(renameat2_link); renameat2_link = NULL; }
    if (unlinkat_link)  { bpf_link__destroy(unlinkat_link);  unlinkat_link  = NULL; }
    if (g_rb)           { ring_buffer__free(g_rb);           g_rb           = NULL; }
    if (g_skel)         { ransomware_burst_bpf__destroy(g_skel); g_skel     = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void rb_print_summary(void)
{
    if (rb_stat_count == 0) return;

    printf("[burst] --- Ransomware Burst Summary -----------------------------\n");
    printf("[burst]   PID     Comm             Bursts  MaxTouch  MaxDistinct\n");
    for (int i = 0; i < rb_stat_count; i++) {
        printf("[burst]  %6u  %-16s  %6u  %8u  %11d\n",
               rb_stats[i].pid, rb_stats[i].comm, rb_stats[i].burst_count,
               rb_stats[i].max_touch_count, rb_stats[i].max_distinct);
    }
    printf("[burst]  %d process%s triggered a burst\n",
           rb_stat_count, rb_stat_count == 1 ? "" : "es");
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_ransomware_burst = {
    .name          = "ransomware-burst",
    .description   = "Detect rename/unlink bursts on external storage (rapid rename+delete "
                      "across many distinct files -- classic crypto-ransomware signal; "
                      "stealthy -- kprobes, zero uprobes)",
    .setup         = rb_setup,
    .teardown      = rb_teardown,
    .print_summary = rb_print_summary,
};
