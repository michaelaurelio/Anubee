// SPDX-License-Identifier: GPL-2.0
// `ares mod screencapture-detect` — userspace analyzer for MediaProjection
// screen-capture session abuse. Owns the screencapture_detect BPF skeleton
// lifecycle; the dispatcher in mod.c drives the poll loop and teardown
// order. Kernel side: src/modules/screencapture_detect.bpf.c (passive Binder-call
// counter only -- see design doc for why a burst-threshold signal doesn't
// transfer to this technique). Detection is a background thread polling
// `dumpsys activity services <pkg>` for an active mediaProjection
// foreground service, same stub-ring-buffer precedent as fileless-detect.
// Parsing: src/modules/screencapture_detect_parse.c.
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

// ── per-pid tally (tallied unconditionally so summary survives -o) ─────────

#define MEDIAPROJ_STAT_MAX 64

typedef struct {
    __u32    pid;
    char     comm[TASK_COMM_LEN];
    uint32_t sessions;
    uint64_t total_binder_calls;
} mediaproj_stat_t;

static mediaproj_stat_t mediaproj_stats[MEDIAPROJ_STAT_MAX];
static int              mediaproj_stat_count = 0;
static pthread_mutex_t  mediaproj_stat_lock = PTHREAD_MUTEX_INITIALIZER;

static void mediaproj_stat_add(__u32 pid, const char *comm, __u64 binder_calls)
{
    pthread_mutex_lock(&mediaproj_stat_lock);
    for (int i = 0; i < mediaproj_stat_count; i++) {
        if (mediaproj_stats[i].pid == pid) {
            mediaproj_stats[i].sessions++;
            mediaproj_stats[i].total_binder_calls += binder_calls;
            pthread_mutex_unlock(&mediaproj_stat_lock);
            return;
        }
    }
    if (mediaproj_stat_count < MEDIAPROJ_STAT_MAX) {
        mediaproj_stats[mediaproj_stat_count].pid = pid;
        snprintf(mediaproj_stats[mediaproj_stat_count].comm, TASK_COMM_LEN, "%s", comm);
        mediaproj_stats[mediaproj_stat_count].sessions = 1;
        mediaproj_stats[mediaproj_stat_count].total_binder_calls = binder_calls;
        mediaproj_stat_count++;
    }
    pthread_mutex_unlock(&mediaproj_stat_lock);
}

static struct screencapture_detect_bpf *g_skel = NULL;
static struct bpf_link            *mediaproj_ff = NULL;
static struct bpf_link            *binder_link = NULL;
static struct ring_buffer         *g_rb = NULL;
static struct ares_mod_ctx        *g_mc = NULL;

// ── system_server pid resolve (pre-attach, gates the passive BPF counter) ──

static void mediaproj_resolve_sys_server_pid(__u32 *out)
{
    *out = 0;
    char out_buf[64];
    if (ares_sh_exec("pidof system_server", out_buf, sizeof(out_buf)) < 0)
        return;
    *out = (__u32)strtoul(out_buf, NULL, 10);
}

// ── dumpsys session-state poll thread ───────────────────────────────────

#define MEDIAPROJ_POLL_MS 1000

enum mediaproj_state { MP_UNKNOWN = -1, MP_INACTIVE = 0, MP_ACTIVE = 1 };

static pthread_t    g_poll_thread;
static volatile int  g_poll_stop = 0;
static int           g_poll_thread_running = 0;
static enum mediaproj_state g_mp_state = MP_UNKNOWN;

static __u64 mediaproj_read_and_reset_binder_count(__u32 pid)
{
    if (!g_skel) return 0;
    int fd = bpf_map__fd(g_skel->maps.binder_count_map);
    __u64 val = 0;
    bpf_map_lookup_elem(fd, &pid, &val);
    bpf_map_delete_elem(fd, &pid);
    return val;
}

static void mediaproj_emit_one(__u32 pid, const char *comm, __u64 binder_calls)
{
    struct screencapture_detect_event e = {0};
    e.h.type = MOD_EV_SCREENCAPTURE_DETECT;
    e.h.pid  = pid;
    e.h.tid  = pid;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    e.ts_ns = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
    e.binder_calls_context = binder_calls;
    snprintf(e.comm, TASK_COMM_LEN, "%s", comm);

    mediaproj_stat_add(pid, comm, binder_calls);

    if (!g_mc->quiet) {
        printf("[screencapture-detect] PID:%-6d (%s) active MediaProjection session "
               "(%llu system_server Binder calls observed)\n",
               pid, comm, (unsigned long long)binder_calls);
    }
    if (g_mc->sink != NULL) {
        mod_emit_screencapture_detect(&g_mc->sink->jb, &e);
        ares_sink_emit(g_mc->sink);
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
        if (ares_sh_exec(cmd, out, sizeof(out)) < 0) {
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
            __u64 binder_calls = upid ? mediaproj_read_and_reset_binder_count(upid) : 0;
            char comm[TASK_COMM_LEN] = "?";
            if (upid) mediaproj_read_comm((int)upid, comm, sizeof(comm));
            mediaproj_emit_one(upid, comm, binder_calls);
        }
        g_mp_state = now;
    }
    return NULL;
}

// ---- ring-buffer callback ---------------------------------------------------
// Unused: detection flows through the poll thread above, not events_rb.
// Kept only because ring_buffer__new() requires a non-NULL sample callback
// and ares_analyzer_t.setup() must return a non-NULL ring_buffer* for the
// dispatcher's poll loop -- same precedent as fileless-detect's
// fileless_handle_event.

static int mediaproj_handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)data; (void)sz;
    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *mediaproj_setup(int uid, struct ares_mod_ctx *mc)
{
    g_mc = mc;

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

    __u32 sys_pid = 0, zk = 0;
    mediaproj_resolve_sys_server_pid(&sys_pid);
    if (sys_pid == 0)
        fprintf(stderr, "mod screencapture-detect: could not resolve system_server pid "
                        "(pidof failed) -- Binder-call context will always read 0\n");
    bpf_map_update_elem(bpf_map__fd(g_skel->maps.sys_server_pid_map), &zk, &sys_pid, BPF_ANY);

    binder_link = bpf_program__attach(g_skel->progs.on_binder_transaction);
    if (!binder_link) {
        fprintf(stderr, "mod screencapture-detect: tp/binder/binder_transaction unavailable, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        mediaproj_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
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

    if (binder_link)  { bpf_link__destroy(binder_link);  binder_link  = NULL; }
    if (mediaproj_ff) { bpf_link__destroy(mediaproj_ff); mediaproj_ff = NULL; }
    if (g_rb)         { ring_buffer__free(g_rb);         g_rb         = NULL; }
    if (g_skel)       { screencapture_detect_bpf__destroy(g_skel); g_skel  = NULL; }
}

// ---- summary ----------------------------------------------------------------
// Lock-free reads of mediaproj_stats/mediaproj_stat_count are safe here only
// because mod.c always calls teardown() (joining the poll thread) before
// print_summary()/emit_summary() -- same invariant fileless-detect documents.

static void mediaproj_print_summary(void)
{
    if (mediaproj_stat_count == 0) return;

    printf("[screencapture-detect] --- Screen-Capture Detection Summary ---------------------------\n");
    printf("[screencapture-detect]   PID     Comm             Sessions  BinderCalls\n");
    for (int i = 0; i < mediaproj_stat_count; i++) {
        printf("[screencapture-detect]  %6u  %-16s  %8u  %11llu\n",
               mediaproj_stats[i].pid, mediaproj_stats[i].comm,
               mediaproj_stats[i].sessions,
               (unsigned long long)mediaproj_stats[i].total_binder_calls);
    }
    printf("[screencapture-detect]  %d process%s had an active MediaProjection session\n",
           mediaproj_stat_count, mediaproj_stat_count == 1 ? "" : "es");
}

static void mediaproj_emit_summary(struct ares_sink *s)
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
        jb_s(j, ",\"sessions\":");   jb_u64(j, mediaproj_stats[i].sessions);
        jb_s(j, ",\"total_binder_calls\":"); jb_u64(j, mediaproj_stats[i].total_binder_calls);
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    ares_sink_emit(s);
}

static unsigned long long mediaproj_drops(void)
{
    return 0;   // nothing is ever submitted to events_rb or dropped from
                // binder_count_map -- this is the first mod analyzer with no
                // real drop concept, see design doc's Known limitations.
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_screencapture_detect = {
    .name          = "screencapture-detect",
    .description   = "Detect an active MediaProjection screen-capture session "
                      "(live screen streaming to C2 -- the escalation behind "
                      "OverlayPhantom and current 2026 Android banking trojans; "
                      "stealthy -- dumpsys poll + tracepoint context only, zero "
                      "uprobes)",
    .setup         = mediaproj_setup,
    .teardown      = mediaproj_teardown,
    .print_summary = mediaproj_print_summary,
    .emit_summary  = mediaproj_emit_summary,
    .drops         = mediaproj_drops,
};
