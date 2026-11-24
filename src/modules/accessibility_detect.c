// SPDX-License-Identifier: GPL-2.0
// `anubee mod accessibility-detect` — what the traced app's own
// AccessibilityService does: calls on IAccessibilityServiceConnection, named
// from the device's framework jars and mapped to abuse categories
// (screen_read, action, gesture, global_action, screenshot, input_method).
// One alert per (process, category); every call is counted. Kernel side:
// src/modules/accessibility_detect.bpf.c. Classification:
// src/modules/accessibility_detect_classify.c.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "accessibility_detect.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/accessibility_detect_classify.h"
#include "modules/binder_names_load.h"

// ── per-pid tally ──────────────────────────────────────────────────────────

#define A11Y_STAT_MAX 64

typedef struct {
    __u32              pid;
    char               comm[TASK_COMM_LEN];
    unsigned           alerted;               // bit per category already reported
    unsigned long long calls[A11Y_CAT_N];     // filled from a11y_counts at teardown
} a11y_stat_t;

static a11y_stat_t a11y_stats[A11Y_STAT_MAX];
static int         a11y_stat_count = 0;

static a11y_stat_t *a11y_stat_get(__u32 pid, const char *comm)
{
    for (int i = 0; i < a11y_stat_count; i++)
        if (a11y_stats[i].pid == pid)
            return &a11y_stats[i];
    if (a11y_stat_count >= A11Y_STAT_MAX) return NULL;
    a11y_stat_t *s = &a11y_stats[a11y_stat_count++];
    memset(s, 0, sizeof *s);
    s->pid = pid;
    snprintf(s->comm, TASK_COMM_LEN, "%s", comm ? comm : "");
    return s;
}

// ── accessibility-service grant check (one-time, post-attach) ──────────────

// Tri-state: 1 = granted, 0 = checked and not granted, -1 = unknown (pkg
// unresolved, never checked).
static int g_a11y_granted = -1;

static void a11y_check_service_granted(const char *pkg)
{
    if (!pkg) return;
    char out[512];
    if (anubee_sh_exec("settings get secure enabled_accessibility_services", out, sizeof(out)) < 0)
        return;
    g_a11y_granted = strstr(out, pkg) ? 1 : 0;
}

static struct accessibility_detect_bpf *g_skel = NULL;
static struct bpf_link       *a11y_ff = NULL;
static struct ring_buffer    *g_rb = NULL;
static struct bpf_link       *binder_link = NULL;
static struct binder_names   *g_names = NULL;

static const char *a11y_method(__u32 code)
{
    return g_names ? binder_names_lookup(g_names, A11Y_SERVICE_IFACE, code) : NULL;
}

// ---- ring-buffer callback ---------------------------------------------------

static int a11y_handle_event(void *ctx, void *data, size_t sz)
{
    struct anubee_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_ACCESSIBILITY_DETECT || sz < sizeof(struct accessibility_detect_event))
        return 0;

    const struct accessibility_detect_event *e = data;
    const char *method = a11y_method(e->code);
    int cat = a11y_classify_method(method);
    a11y_stat_t *st = a11y_stat_get(e->h.pid, e->comm);
    if (!a11y_category_alerts(cat) || !st || (st->alerted & (1u << cat)))
        return 0;
    st->alerted |= 1u << cat;

    if (!mc->quiet) {
        printf("[accessibility-detect] PID:%-6d (%s) %-13s %s", e->h.pid, e->comm,
               a11y_category_name(cat), method ? method : "?");
        if (!method) printf("#%u", e->code);
        printf("%s\n", g_a11y_granted == 1 ? " [service granted]" : "");
    }

    if (mc->sink != NULL) {
        mod_emit_accessibility_detect(&mc->sink->jb, e, a11y_category_name(cat), method,
                                      g_a11y_granted);
        anubee_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static void a11y_teardown(void);

static struct ring_buffer *a11y_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_names = binder_names_load_device(NULL);
    if (!a11y_method(0) && !a11y_method(1))   // codes start at 1; 0 is never valid
        fprintf(stderr, "mod accessibility-detect: %s method names not found in the "
                        "framework jars -- calls will show as #code / category other\n",
                A11Y_SERVICE_IFACE);

    g_skel = accessibility_detect_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod accessibility-detect: failed to open BPF skeleton\n");
        return NULL;
    }
    if (accessibility_detect_bpf__load(g_skel)) {
        fprintf(stderr, "mod accessibility-detect: failed to load BPF\n");
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

    // Arm the in-kernel token match before attach.
    __u32 zk = 0;
    __u64 h = binder_descriptor_hash(A11Y_SERVICE_IFACE);
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.a11y_token), &zk, &h, BPF_ANY);

    binder_link = bpf_program__attach(g_skel->progs.on_binder_transaction);
    if (!binder_link) {
        fprintf(stderr, "mod accessibility-detect: kprobe/binder_transaction unavailable (%s), aborting\n",
                strerror(errno));
        goto err;
    }

    // Deliberately after attach, not before: this shells out (settings get)
    // and can take hundreds of ms+ on real hardware, same ordering rationale
    // as massdelete_detect's MANAGE_EXTERNAL_STORAGE check.
    a11y_check_service_granted(mc->pkg);
    if (g_a11y_granted == 1)
        printf("[accessibility-detect] target holds a granted Accessibility Service\n");

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        a11y_ff = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (!a11y_ff) fprintf(stderr, "mod accessibility-detect: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            a11y_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod accessibility-detect: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    a11y_teardown();
    return NULL;
}

// Per-(process, code) call counts from the kernel, folded into categories.
static void a11y_snapshot_counts(void)
{
    if (!g_skel) return;
    int fd = bpf_map__fd(g_skel->maps.a11y_counts);
    struct a11y_key k, next, *prev = NULL;
    while (bpf_map_get_next_key(fd, prev, &next) == 0) {
        __u64 c = 0;
        if (bpf_map_lookup_elem(fd, &next, &c) == 0) {
            a11y_stat_t *st = a11y_stat_get(next.tgid, NULL);
            if (st) st->calls[a11y_classify_method(a11y_method(next.code))] += c;
        }
        k = next;
        prev = &k;
    }
}

static void a11y_teardown(void)
{
    if (a11y_ff)     { bpf_link__destroy(a11y_ff);     a11y_ff     = NULL; }
    if (binder_link) { bpf_link__destroy(binder_link); binder_link = NULL; }
    if (g_rb)        { ring_buffer__free(g_rb);        g_rb        = NULL; }
    a11y_snapshot_counts();
    if (g_skel)      { accessibility_detect_bpf__destroy(g_skel); g_skel = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void a11y_print_summary(void)
{
    if (a11y_stat_count == 0) return;

    printf("[accessibility-detect] --- Accessibility-service calls by category ---\n");
    for (int i = 0; i < a11y_stat_count; i++) {
        printf("[accessibility-detect]  %6u  %-16s", a11y_stats[i].pid, a11y_stats[i].comm);
        for (int c = 1; c < A11Y_CAT_N; c++)
            if (a11y_stats[i].calls[c])
                printf(" %s=%llu", a11y_category_name(c), a11y_stats[i].calls[c]);
        if (a11y_stats[i].calls[A11Y_OTHER])
            printf(" other=%llu", a11y_stats[i].calls[A11Y_OTHER]);
        printf("\n");
    }
    printf("[accessibility-detect]  %d process%s used an Accessibility service\n",
           a11y_stat_count, a11y_stat_count == 1 ? "" : "es");
}

static void a11y_emit_summary(struct anubee_sink *s)
{
    if (a11y_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"accessibility_detect_summary\"");
    jb_s(j, ",\"process_count\":"); jb_u64(j, (unsigned long long)a11y_stat_count);
    jb_s(j, ",\"processes\":[");
    for (int i = 0; i < a11y_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");        jb_u64(j, a11y_stats[i].pid);
        jb_s(j, ",\"comm\":\"");     jb_esc(j, a11y_stats[i].comm); jb_c(j, '"');
        jb_s(j, ",\"calls\":{");
        for (int c = 0; c < A11Y_CAT_N; c++) {
            if (c) jb_c(j, ',');
            jb_c(j, '"'); jb_s(j, a11y_category_name(c)); jb_s(j, "\":");
            jb_u64(j, a11y_stats[i].calls[c]);
        }
        jb_s(j, "}}");
    }
    jb_c(j, ']');
    jb_c(j, '}');
    anubee_sink_emit(s);
}

static unsigned long long a11y_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const anubee_analyzer_t analyzer_accessibility_detect = {
    .name          = "accessibility-detect",
    .description   = "What the app's own Accessibility Service does: screen reading, "
                      "clicks/text entry, gestures, global actions, screenshots, keyboard "
                      "switching -- from its IAccessibilityServiceConnection calls (the "
                      "dominant technique in current Android banking trojans; stealthy -- "
                      "kprobe only, zero uprobes)",
    .setup         = a11y_setup,
    .teardown      = a11y_teardown,
    .print_summary = a11y_print_summary,
    .emit_summary  = a11y_emit_summary,
    .drops         = a11y_drops,
};
