// SPDX-License-Identifier: GPL-2.0
// `ares mod a11y-abuse` — userspace analyzer for the Binder-transaction-burst
// signal. Owns the a11y_abuse BPF skeleton lifecycle; the dispatcher in mod.c
// drives the poll loop and teardown order. Kernel side:
// src/modules/a11y_abuse.bpf.c. Classification:
// src/modules/a11y_abuse_classify.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "a11y_abuse.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/a11y_abuse_classify.h"

// ── per-pid tally (tallied unconditionally so summary survives -o) ─────────

#define A11Y_STAT_MAX 64

typedef struct {
    __u32    pid;
    char     comm[TASK_COMM_LEN];
    uint32_t burst_count;
    uint32_t max_touch_count;
} a11y_stat_t;

static a11y_stat_t a11y_stats[A11Y_STAT_MAX];
static int         a11y_stat_count = 0;

static void a11y_stat_add(__u32 pid, const char *comm, int touch_count)
{
    for (int i = 0; i < a11y_stat_count; i++) {
        if (a11y_stats[i].pid == pid) {
            a11y_stats[i].burst_count++;
            if ((uint32_t)touch_count > a11y_stats[i].max_touch_count)
                a11y_stats[i].max_touch_count = (uint32_t)touch_count;
            return;
        }
    }
    if (a11y_stat_count >= A11Y_STAT_MAX) return;
    a11y_stats[a11y_stat_count].pid = pid;
    snprintf(a11y_stats[a11y_stat_count].comm, TASK_COMM_LEN, "%s", comm);
    a11y_stats[a11y_stat_count].burst_count = 1;
    a11y_stats[a11y_stat_count].max_touch_count = (uint32_t)touch_count;
    a11y_stat_count++;
}

// ── system_server pid resolve (pre-attach, gates in-kernel) ────────────────

static void a11y_resolve_sys_server_pid(__u32 *out)
{
    *out = 0;
    char out_buf[64];
    if (ares_sh_exec("pidof system_server", out_buf, sizeof(out_buf)) < 0)
        return;
    *out = (__u32)strtoul(out_buf, NULL, 10);
}

// ── accessibility-service grant check (one-time, post-attach) ──────────────

// Tri-state: 1 = granted, 0 = checked and not granted, -1 = unknown (pkg
// unresolved, never checked).
static int g_a11y_granted = -1;

static void a11y_check_service_granted(const char *pkg)
{
    if (!pkg) return;
    char out[512];
    if (ares_sh_exec("settings get secure enabled_accessibility_services", out, sizeof(out)) < 0)
        return;
    g_a11y_granted = strstr(out, pkg) ? 1 : 0;
}

// Single short tag for the console line.
static const char *a11y_tag(unsigned categories)
{
    if ((categories & A11Y_BURST_DETECTED) && (categories & A11Y_SERVICE_GRANTED))
        return "[a11y-abuse]";
    if (categories & A11Y_BURST_DETECTED)
        return "[a11y-burst]";
    // Unreachable while the BPF side only ever emits at count==A11Y_THRESHOLD
    // (a11y_abuse.bpf.c's record_call): kept for the same defensive-gate
    // reasoning classify_a11y() itself documents, mirrors burst_tag()'s
    // equivalent fallback in ransomware_burst.c.
    return "[a11y-low-confidence]";
}

static struct a11y_abuse_bpf *g_skel = NULL;
static struct bpf_link       *a11y_ff = NULL;
static struct ring_buffer    *g_rb = NULL;
static struct bpf_link       *binder_link = NULL;

// ---- ring-buffer callback ---------------------------------------------------

static int a11y_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_A11Y_ABUSE || sz < sizeof(struct a11y_abuse_event))
        return 0;

    const struct a11y_abuse_event *e = data;
    unsigned categories = classify_a11y((int)e->touch_count, g_a11y_granted);
    a11y_stat_add(e->h.pid, e->comm, (int)e->touch_count);

    if (!mc->quiet) {
        printf("[a11y] %-22s PID:%-6d (%s) %u binder calls to system_server, %ums window\n",
               a11y_tag(categories), e->h.pid, e->comm, e->touch_count, e->window_ms);
    }

    if (mc->sink != NULL) {
        mod_emit_a11y_abuse(&mc->sink->jb, e, g_a11y_granted);
        ares_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *a11y_setup(int uid, struct ares_mod_ctx *mc)
{
    g_skel = a11y_abuse_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod a11y-abuse: failed to open BPF skeleton\n");
        return NULL;
    }
    if (a11y_abuse_bpf__load(g_skel)) {
        fprintf(stderr, "mod a11y-abuse: failed to load BPF\n");
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

    // Resolve system_server's pid BEFORE attach: the tracepoint gate reads
    // this map on every fired event, so it must be armed before the program
    // goes live. A resolve failure leaves it 0 (gate never matches -- fails
    // closed on the gate, not a crash); logged so an empty run isn't mistaken
    // for "nothing happened".
    __u32 sys_pid = 0, zk = 0;
    a11y_resolve_sys_server_pid(&sys_pid);
    if (sys_pid == 0)
        fprintf(stderr, "mod a11y-abuse: could not resolve system_server pid (pidof failed) -- gate will never match\n");
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.sys_server_pid_map), &zk, &sys_pid, BPF_ANY);

    binder_link = bpf_program__attach(g_skel->progs.on_binder_transaction);
    if (!binder_link) {
        fprintf(stderr, "mod a11y-abuse: tp/binder/binder_transaction unavailable, aborting\n");
        goto err;
    }

    // Deliberately after attach, not before: this shells out (settings get)
    // and can take hundreds of ms+ on real hardware, same ordering rationale
    // as ransomware_burst's MANAGE_EXTERNAL_STORAGE check.
    a11y_check_service_granted(mc->pkg);
    if (g_a11y_granted == 1)
        printf("[a11y] target holds a granted Accessibility Service\n");

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        a11y_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!a11y_ff) fprintf(stderr, "mod a11y-abuse: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            a11y_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod a11y-abuse: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (a11y_ff)     { bpf_link__destroy(a11y_ff);     a11y_ff     = NULL; }
    if (binder_link) { bpf_link__destroy(binder_link); binder_link = NULL; }
    if (g_skel)      { a11y_abuse_bpf__destroy(g_skel); g_skel     = NULL; }
    return NULL;
}

static void a11y_teardown(void)
{
    if (a11y_ff)     { bpf_link__destroy(a11y_ff);     a11y_ff     = NULL; }
    if (binder_link) { bpf_link__destroy(binder_link); binder_link = NULL; }
    if (g_rb)        { ring_buffer__free(g_rb);        g_rb        = NULL; }
    if (g_skel)      { a11y_abuse_bpf__destroy(g_skel); g_skel     = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void a11y_print_summary(void)
{
    if (a11y_stat_count == 0) return;

    printf("[a11y] --- Accessibility Abuse Summary ---------------------------\n");
    printf("[a11y]   PID     Comm             Bursts  MaxTouch\n");
    for (int i = 0; i < a11y_stat_count; i++) {
        printf("[a11y]  %6u  %-16s  %6u  %8u\n",
               a11y_stats[i].pid, a11y_stats[i].comm, a11y_stats[i].burst_count,
               a11y_stats[i].max_touch_count);
    }
    printf("[a11y]  %d process%s triggered a burst\n",
           a11y_stat_count, a11y_stat_count == 1 ? "" : "es");
}

static void a11y_emit_summary(struct ares_sink *s)
{
    if (a11y_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"a11y_abuse_summary\"");
    jb_s(j, ",\"process_count\":"); jb_u64(j, (unsigned long long)a11y_stat_count);
    jb_s(j, ",\"processes\":[");
    for (int i = 0; i < a11y_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");        jb_u64(j, a11y_stats[i].pid);
        jb_s(j, ",\"comm\":\"");     jb_esc(j, a11y_stats[i].comm); jb_c(j, '"');
        jb_s(j, ",\"bursts\":");     jb_u64(j, a11y_stats[i].burst_count);
        jb_s(j, ",\"max_touch_count\":"); jb_u64(j, a11y_stats[i].max_touch_count);
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    ares_sink_emit(s);
}

static unsigned long long a11y_drops(void)
{
    return g_skel ? ares_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_a11y_abuse = {
    .name          = "a11y-abuse",
    .description   = "Detect Binder-transaction bursts to system_server while the traced "
                      "app holds a granted Accessibility Service (dominant technique in "
                      "2025-2026 Android banking trojans -- overlay/ATS fraud, screen "
                      "reading, security-prompt bypass; stealthy -- tracepoint only, zero "
                      "uprobes)",
    .setup         = a11y_setup,
    .teardown      = a11y_teardown,
    .print_summary = a11y_print_summary,
    .emit_summary  = a11y_emit_summary,
    .drops         = a11y_drops,
};
