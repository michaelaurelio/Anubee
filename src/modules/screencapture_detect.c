// SPDX-License-Identifier: GPL-2.0
// `anubee mod screencapture-detect` — how far a screen-capture attempt got,
// per process, as stages (screencapture_detect_parse.h):
//   fgs_declared     -- a background thread polls `dumpsys activity services
//                       <pkg>` for a mediaProjection-type foreground service
//                       (needs a package; shows the attempt even if the user
//                       then declines the consent prompt);
//   projection_start -- the app's IMediaProjection.start Binder call;
//   virtual_display  -- IDisplayManager.createVirtualDisplay (reported only
//                       after one of the above: apps also use virtual
//                       displays for Presentation/casting).
// Binder calls come from src/modules/screencapture_detect.bpf.c and are
// named from the framework jars (binder_names_load.c).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "screencapture_detect.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/screencapture_detect_parse.h"
#include "modules/binder_names_load.h"

// ── per-pid tally (dispatcher thread only: ring callback, tick, teardown) ──

#define MEDIAPROJ_STAT_MAX 64

typedef struct {
    __u32    pid;
    char     comm[TASK_COMM_LEN];
    unsigned seen;          // bit per stage observed
    unsigned alerted;       // bit per stage reported
    uint32_t sessions;      // fgs_declared transitions
} mediaproj_stat_t;

static mediaproj_stat_t mediaproj_stats[MEDIAPROJ_STAT_MAX];
static int              mediaproj_stat_count = 0;

static mediaproj_stat_t *mediaproj_stat_get(__u32 pid, const char *comm)
{
    for (int i = 0; i < mediaproj_stat_count; i++)
        if (mediaproj_stats[i].pid == pid)
            return &mediaproj_stats[i];
    if (mediaproj_stat_count >= MEDIAPROJ_STAT_MAX) return NULL;
    mediaproj_stat_t *st = &mediaproj_stats[mediaproj_stat_count++];
    memset(st, 0, sizeof *st);
    st->pid = pid;
    snprintf(st->comm, TASK_COMM_LEN, "%s", comm);
    return st;
}

static struct screencapture_detect_bpf *g_skel = NULL;
static struct bpf_link            *mediaproj_ff = NULL;
static struct bpf_link            *binder_link = NULL;
static struct ring_buffer         *g_rb = NULL;
static struct anubee_mod_ctx        *g_mc = NULL;
static struct binder_names        *g_names = NULL;

static const char *const k_sc_ifaces[] = { SC_IFACE_PROJECTION, SC_IFACE_DISPLAY };
static __u64 g_sc_hash[2];

// ── dumpsys session-state poll thread ───────────────────────────────────

#define MEDIAPROJ_POLL_MS 1000

enum mediaproj_state { MP_UNKNOWN = -1, MP_INACTIVE = 0, MP_ACTIVE = 1 };

static pthread_t    g_poll_thread;
static volatile int  g_poll_stop = 0;
static int           g_poll_thread_running = 0;
static enum mediaproj_state g_mp_state = MP_UNKNOWN;

// Hand-off from the dumpsys poll thread to the dispatcher thread: the sink is
// single-writer (see anubee_analyzer_t.tick), so the poll thread only records
// a detected session here and mediaproj_tick() emits it. One slot suffices:
// sessions are detected on 1s dumpsys polls, the dispatcher drains every
// <=100ms; a second session landing before a drain overwrites the first
// (counted in g_pending_overwritten, surfaced at teardown).
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    int   valid;
    __u32 pid;
    char  comm[TASK_COMM_LEN];
    __u64 ts_ns;
} g_pending;
static unsigned long g_pending_overwritten = 0;

// Report one stage for a process: console line + record, once per
// (process, stage) -- except fgs_declared, reported per new session.
static void mediaproj_report(const struct screencapture_detect_event *e, int stage,
                             const char *iface, const char *method)
{
    mediaproj_stat_t *st = mediaproj_stat_get(e->h.pid, e->comm);
    if (!st) return;
    unsigned before = st->seen;
    st->seen |= 1u << stage;
    if (stage == SC_FGS_DECLARED) st->sessions++;
    else if (st->alerted & (1u << stage)) return;
    if (!sc_stage_alerts(stage, before)) return;
    st->alerted |= 1u << stage;

    if (!g_mc->quiet) {
        printf("[screencapture-detect] PID:%-6d (%s) %-16s", e->h.pid, e->comm, sc_stage_name(stage));
        if (method) {
            const char *dot = strrchr(iface, '.');
            printf(" %s.%s", dot ? dot + 1 : iface, method);
        } else {
            printf(" mediaProjection foreground service running");
        }
        printf("\n");
    }
    if (g_mc->sink != NULL) {
        mod_emit_screencapture_detect(&g_mc->sink->jb, e, sc_stage_name(stage), iface, method);
        anubee_sink_emit(g_mc->sink);
    }
}

// dumpsys's ServiceRecord block doesn't carry a friendly comm string, so it's
// read straight from /proc/<pid>/comm -- best-effort, "?" on any failure.
static void mediaproj_read_comm(int pid, char *out, size_t outsz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(out, outsz, "?"); return; }
    if (!fgets(out, (int)outsz, f)) snprintf(out, outsz, "?");
    fclose(f);
    size_t n = strlen(out);
    if (n && out[n - 1] == '\n') out[n - 1] = 0;
}

static void *mediaproj_poll_loop(void *arg)
{
    (void)arg;
    while (!g_poll_stop) {
        usleep(MEDIAPROJ_POLL_MS * 1000);
        if (!g_mc->pkg) continue;   // no package to query (e.g. -p mode, unresolved)

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "dumpsys activity services %s", g_mc->pkg);
        char out[8192];
        if (anubee_sh_exec(cmd, out, sizeof(out)) < 0) {
            g_mp_state = MP_UNKNOWN;
            continue;
        }

        int pid = -1;
        int active = screencapture_detect_parse_dumpsys(out, g_mc->pkg, &pid);
        if (active < 0) {
            g_mp_state = MP_UNKNOWN;
            continue;
        }

        enum mediaproj_state now = active ? MP_ACTIVE : MP_INACTIVE;
        if (g_mp_state != MP_ACTIVE && now == MP_ACTIVE) {
            __u32 upid = pid > 0 ? (__u32)pid : 0;
            char comm[TASK_COMM_LEN] = "?";
            if (upid) mediaproj_read_comm((int)upid, comm, sizeof(comm));
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            pthread_mutex_lock(&g_pending_lock);
            if (g_pending.valid) g_pending_overwritten++;
            g_pending.valid = 1;
            g_pending.pid = upid;
            snprintf(g_pending.comm, sizeof(g_pending.comm), "%s", comm);
            g_pending.ts_ns = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
            pthread_mutex_unlock(&g_pending_lock);
        }
        g_mp_state = now;
    }
    return NULL;
}

// Dispatcher-thread drain of the hand-off slot (anubee_analyzer_t.tick). Also
// called from teardown after the poll thread is joined, so a session detected
// after the dispatcher's last pass is still emitted (the sink is open then).
static void mediaproj_tick(void)
{
    pthread_mutex_lock(&g_pending_lock);
    int valid = g_pending.valid;
    __u32 pid = g_pending.pid;
    char comm[TASK_COMM_LEN];
    snprintf(comm, sizeof(comm), "%s", g_pending.comm);
    __u64 ts_ns = g_pending.ts_ns;
    g_pending.valid = 0;
    pthread_mutex_unlock(&g_pending_lock);

    if (valid) {
        struct screencapture_detect_event e = {0};
        e.h.type = MOD_EV_SCREENCAPTURE_DETECT;
        e.h.pid  = pid;
        e.h.tid  = pid;
        e.ts_ns  = ts_ns;
        snprintf(e.comm, TASK_COMM_LEN, "%s", comm);
        mediaproj_report(&e, SC_FGS_DECLARED, NULL, NULL);
    }
}

// ---- ring-buffer callback: first call per (process, interface, code) ------

static int mediaproj_handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    const struct trace_event_header *hdr = data;
    if (hdr->type != MOD_EV_SCREENCAPTURE_DETECT || sz < sizeof(struct screencapture_detect_event))
        return 0;
    const struct screencapture_detect_event *e = data;
    const char *iface = NULL;
    for (size_t i = 0; i < 2; i++)
        if (e->token_hash == g_sc_hash[i]) iface = k_sc_ifaces[i];
    if (!iface) return 0;
    const char *method = g_names ? binder_names_lookup(g_names, iface, e->code) : NULL;
    int stage = sc_stage_of(iface, method);
    if (stage != SC_NONE)
        mediaproj_report(e, stage, iface, method);
    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *mediaproj_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_mc = mc;
    g_names = binder_names_load_device(NULL);
    if (!g_names || !binder_names_lookup(g_names, SC_IFACE_PROJECTION, 1))
        fprintf(stderr, "mod screencapture-detect: MediaProjection method names not found in "
                        "the framework jars -- only the dumpsys stage will be reported\n");

    g_skel = screencapture_detect_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod screencapture-detect: failed to open BPF skeleton\n");
        return NULL;
    }
    if (screencapture_detect_bpf__load(g_skel)) {
        fprintf(stderr, "mod screencapture-detect: failed to load BPF\n");
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

    for (size_t i = 0; i < 2; i++) {
        g_sc_hash[i] = binder_descriptor_hash(k_sc_ifaces[i]);
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.sc_tokens), &g_sc_hash[i], &one, BPF_ANY);
    }

    binder_link = bpf_program__attach(g_skel->progs.on_binder_transaction);
    if (!binder_link) {
        fprintf(stderr, "mod screencapture-detect: kprobe/binder_transaction unavailable, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        mediaproj_ff = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (!mediaproj_ff) fprintf(stderr, "mod screencapture-detect: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            mediaproj_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod screencapture-detect: failed to create ring buffer\n");
        goto err;
    }

    g_mp_state = MP_UNKNOWN;
    g_poll_stop = 0;
    if (pthread_create(&g_poll_thread, NULL, mediaproj_poll_loop, NULL) != 0) {
        fprintf(stderr, "mod screencapture-detect: failed to start dumpsys poll thread\n");
        goto err;
    }
    g_poll_thread_running = 1;

    return g_rb;

err:
    if (binder_link)  { bpf_link__destroy(binder_link);  binder_link  = NULL; }
    if (mediaproj_ff) { bpf_link__destroy(mediaproj_ff); mediaproj_ff = NULL; }
    if (g_rb)         { ring_buffer__free(g_rb);         g_rb         = NULL; }
    if (g_skel)       { screencapture_detect_bpf__destroy(g_skel); g_skel  = NULL; }
    return NULL;
}

static void mediaproj_teardown(void)
{
    if (g_poll_thread_running) {
        g_poll_stop = 1;
        pthread_join(g_poll_thread, NULL);
        g_poll_thread_running = 0;
    }
    mediaproj_tick();   // poll thread is joined: flush a last-moment detection
    if (g_pending_overwritten)
        fprintf(stderr, "mod screencapture-detect: %lu session alert(s) overwritten "
                        "before the dispatcher drained them\n", g_pending_overwritten);

    if (binder_link)  { bpf_link__destroy(binder_link);  binder_link  = NULL; }
    if (mediaproj_ff) { bpf_link__destroy(mediaproj_ff); mediaproj_ff = NULL; }
    if (g_rb)         { ring_buffer__free(g_rb);         g_rb         = NULL; }
    if (g_skel)       { screencapture_detect_bpf__destroy(g_skel); g_skel  = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void mediaproj_print_summary(void)
{
    if (mediaproj_stat_count == 0) return;

    printf("[screencapture-detect] --- Screen-capture stages per process ---\n");
    for (int i = 0; i < mediaproj_stat_count; i++) {
        printf("[screencapture-detect]  %6u  %-16s", mediaproj_stats[i].pid, mediaproj_stats[i].comm);
        for (int st = SC_FGS_DECLARED; st < SC_STAGE_N; st++)
            if (mediaproj_stats[i].seen & (1u << st))
                printf(" %s", sc_stage_name(st));
        if (mediaproj_stats[i].sessions)
            printf(" (%u FGS session%s)", mediaproj_stats[i].sessions,
                   mediaproj_stats[i].sessions == 1 ? "" : "s");
        printf("\n");
    }
}

static void mediaproj_emit_summary(struct anubee_sink *s)
{
    if (mediaproj_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"screencapture_detect_summary\"");
    jb_s(j, ",\"process_count\":"); jb_u64(j, (unsigned long long)mediaproj_stat_count);
    jb_s(j, ",\"processes\":[");
    for (int i = 0; i < mediaproj_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");        jb_u64(j, mediaproj_stats[i].pid);
        jb_s(j, ",\"comm\":\"");     jb_esc(j, mediaproj_stats[i].comm); jb_c(j, '"');
        jb_s(j, ",\"stages\":[");
        int first = 1;
        for (int st = SC_FGS_DECLARED; st < SC_STAGE_N; st++)
            if (mediaproj_stats[i].seen & (1u << st)) {
                if (!first) jb_c(j, ',');
                first = 0;
                jb_c(j, '"'); jb_s(j, sc_stage_name(st)); jb_c(j, '"');
            }
        jb_s(j, "],\"fgs_sessions\":"); jb_u64(j, mediaproj_stats[i].sessions);
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    anubee_sink_emit(s);
}

static unsigned long long mediaproj_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const anubee_analyzer_t analyzer_screencapture_detect = {
    .name          = "screencapture-detect",
    .description   = "Screen-capture attempts by stage: mediaProjection foreground "
                      "service (dumpsys poll), IMediaProjection.start, virtual display "
                      "(live screen streaming to C2 -- the escalation behind "
                      "OverlayPhantom and current Android banking trojans; "
                      "stealthy -- kprobe + dumpsys poll, zero uprobes)",
    .setup         = mediaproj_setup,
    .teardown      = mediaproj_teardown,
    .print_summary = mediaproj_print_summary,
    .emit_summary  = mediaproj_emit_summary,
    .drops         = mediaproj_drops,
    .tick          = mediaproj_tick,
};
