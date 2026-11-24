// SPDX-License-Identifier: GPL-2.0
// `anubee mod perm-watch` — record the traced package's permission state at
// start (baseline) and every change during the run: runtime/install
// permissions, app-op modes, Accessibility / notification-listener /
// device-admin enablement, and role holdership (default SMS, dialer, home...).
// Malware's escalation path -- talk the user into Accessibility, flip
// SYSTEM_ALERT_WINDOW, take the SMS role, become device admin -- shows up here
// as a timeline, joinable on ts_ns with the other analyzers' events.
//
// No BPF program: state comes from the platform shell tools (dumpsys, appops,
// settings), read from our own root process, so nothing touches the target
// (stealthy). The dispatcher still needs a ring to poll, so setup creates an
// empty BPF ring-buffer map (a map, not a program -- nothing is attached).
// A background thread snapshots every PW_POLL_MS and queues the diff; the
// dispatcher tick emits it (the -o sink is single-writer). Parsing/diffing:
// src/modules/perm_watch_parse.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common/analyzer.h"
#include "common/emit.h"
#include "common/launch.h"
#include "common/pkg_name.h"
#include "modules/mod_emit.h"
#include "modules/perm_watch_parse.h"

#define PW_POLL_MS   2000
#define PW_QUEUE_MAX 512
#define PW_OUT_MAX   (256 * 1024)
#define PW_END       "@@ANUBEE_PW_END"

static struct anubee_mod_ctx *g_mc = NULL;
static const char *g_pkg = NULL;
static int g_stub_fd = -1;
static struct ring_buffer *g_rb = NULL;

static struct pw_state g_prev, g_next;   // poll-thread owned after setup
static char g_out[PW_OUT_MAX];           // poll-thread owned after setup

struct pw_change {
    unsigned long long ts_ns;
    char change[12];
    char key[PW_KEY_MAX];
    char old_val[PW_VAL_MAX];  int has_old;
    char new_val[PW_VAL_MAX];  int has_new;
};

static pthread_mutex_t g_q_lock = PTHREAD_MUTEX_INITIALIZER;
static struct pw_change g_q[PW_QUEUE_MAX];
static int g_q_head = 0, g_q_len = 0;
static unsigned long long g_q_dropped = 0;

static pthread_t g_thread;
static volatile int g_stop = 0;
static int g_thread_running = 0;

static unsigned long g_granted = 0, g_revoked = 0, g_changed = 0;
static unsigned long g_snap_failed = 0;

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   // same clock base as bpf_ktime_get_ns
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

// Run cmd with PW_END echoed after it; 0 only if the marker made it back
// (command ran to completion, output not truncated by the buffer).
static int run_marked(const char *cmd)
{
    char full[512];
    snprintf(full, sizeof full, "%s; echo " PW_END, cmd);
    if (anubee_sh_exec(full, g_out, sizeof g_out) < 0)
        return -1;
    char *m = strstr(g_out, PW_END);
    if (!m)
        return -1;
    *m = '\0';
    return 0;
}

// Fill s with the package's current facts. Returns -1 if any source failed,
// so a transient dumpsys failure never reads as "everything revoked".
static int snapshot(struct pw_state *s)
{
    char cmd[400];
    pw_state_init(s);

    // dumpsys package is megabytes for big packages: filter on the device.
    snprintf(cmd, sizeof cmd,
             "dumpsys package %s | grep -e 'granted=true' -e '^Unable to find package'", g_pkg);
    if (run_marked(cmd) != 0) return -1;
    if (strstr(g_out, "Unable to find package"))
        return 0;                       // uninstalled: no facts at all (incl. "installed")
    pw_add_fact(s, "installed", "yes");
    pw_parse_package(s, g_out);

    snprintf(cmd, sizeof cmd, "appops get %s", g_pkg);
    if (run_marked(cmd) != 0) return -1;
    pw_parse_appops(s, g_out);

    if (run_marked("settings get secure enabled_accessibility_services") != 0) return -1;
    pw_parse_component_list(s, "accessibility", g_out, g_pkg);
    if (run_marked("settings get secure enabled_notification_listeners") != 0) return -1;
    pw_parse_component_list(s, "notification-listener", g_out, g_pkg);

    snprintf(cmd, sizeof cmd, "dumpsys device_policy | grep -F '%s/'", g_pkg);
    if (run_marked(cmd) != 0) return -1;
    pw_parse_device_admin(s, g_out, g_pkg);

    if (run_marked("dumpsys role | grep -e 'name=' -e 'holders='") != 0) return -1;
    pw_parse_roles(s, g_out, g_pkg);
    return 0;
}

static void enqueue(const char *key, const char *old_val, const char *new_val, void *ctx)
{
    unsigned long long ts = *(unsigned long long *)ctx;
    pthread_mutex_lock(&g_q_lock);
    if (g_q_len == PW_QUEUE_MAX) {
        g_q_dropped++;
    } else {
        struct pw_change *c = &g_q[(g_q_head + g_q_len) % PW_QUEUE_MAX];
        c->ts_ns = ts;
        snprintf(c->change, sizeof c->change, "%s",
                 !old_val ? "granted" : !new_val ? "revoked" : "changed");
        snprintf(c->key, sizeof c->key, "%s", key);
        c->has_old = old_val != NULL;
        c->has_new = new_val != NULL;
        snprintf(c->old_val, sizeof c->old_val, "%s", old_val ? old_val : "");
        snprintf(c->new_val, sizeof c->new_val, "%s", new_val ? new_val : "");
        g_q_len++;
    }
    pthread_mutex_unlock(&g_q_lock);
}

static void *poll_loop(void *arg)
{
    (void)arg;
    while (!g_stop) {
        for (int i = 0; i < PW_POLL_MS / 100 && !g_stop; i++)
            usleep(100 * 1000);
        if (g_stop) break;
        unsigned long long ts = now_ns();
        if (snapshot(&g_next) != 0) { g_snap_failed++; continue; }
        pw_diff(&g_prev, &g_next, enqueue, &ts);
        memcpy(&g_prev, &g_next, sizeof g_prev);
    }
    return NULL;
}

static void emit_change(unsigned long long ts, const char *change, const char *key,
                        const char *old_val, const char *new_val)
{
    if (!g_mc->quiet) {
        const char *colon = strchr(key, ':');
        printf("[perm-watch] %s %-8s %s", g_pkg, change, pw_category(key));
        if (colon) printf(" %s", colon + 1);   // special-access keys: category is the name
        if (old_val && new_val)  printf(" %s -> %s", old_val, new_val);
        else if (new_val && strcmp(new_val, "granted") && strcmp(new_val, "held") &&
                 strcmp(new_val, "yes"))
            printf(" = %s", new_val);
        printf("\n");
    }
    if (g_mc->sink) {
        g_mc->sink->jb.len = 0;
        mod_emit_perm_change(&g_mc->sink->jb, ts, g_pkg, key, change, old_val, new_val);
        anubee_sink_emit(g_mc->sink);
    }
}

static void pw_tick(void)
{
    for (;;) {
        struct pw_change c;
        pthread_mutex_lock(&g_q_lock);
        if (!g_q_len) { pthread_mutex_unlock(&g_q_lock); return; }
        c = g_q[g_q_head];
        g_q_head = (g_q_head + 1) % PW_QUEUE_MAX;
        g_q_len--;
        pthread_mutex_unlock(&g_q_lock);

        if (!strcmp(c.change, "granted"))      g_granted++;
        else if (!strcmp(c.change, "revoked")) g_revoked++;
        else                                   g_changed++;
        emit_change(c.ts_ns, c.change, c.key, c.has_old ? c.old_val : NULL,
                    c.has_new ? c.new_val : NULL);
    }
}

static int stub_sample(void *ctx, void *data, size_t len)
{
    (void)ctx; (void)data; (void)len;
    return 0;
}

static void pw_teardown(void);

static struct ring_buffer *pw_setup(int uid, struct anubee_mod_ctx *mc)
{
    (void)uid;
    g_mc = mc;
    g_pkg = (mc->pkg && anubee_pkg_name_ok(mc->pkg)) ? mc->pkg : NULL;

    long page = sysconf(_SC_PAGESIZE);
    g_stub_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "pw_stub", 0, 0,
                               (unsigned)(page > 0 ? page : 4096), NULL);
    if (g_stub_fd < 0) {
        fprintf(stderr, "mod perm-watch: cannot create stub ring buffer\n");
        return NULL;
    }
    g_rb = ring_buffer__new(g_stub_fd, stub_sample, NULL, NULL);
    if (!g_rb) { pw_teardown(); return NULL; }
    if (!g_pkg) {
        // Inert rather than fatal, so one unresolvable target (a native
        // daemon under -p) doesn't abort the other analyzers in a triage run.
        fprintf(stderr, "mod perm-watch: warning - no package name to watch (-p pid whose "
                        "package doesn't resolve); perm-watch inactive\n");
        return g_rb;
    }

    // Baseline: taken before the dispatcher launches the app, emitted here on
    // the dispatcher thread (setup runs there, before the poll loop starts).
    if (snapshot(&g_prev) != 0) {
        fprintf(stderr, "mod perm-watch: initial snapshot of '%s' failed "
                        "(dumpsys/appops unavailable?)\n", g_pkg);
        pw_teardown();
        return NULL;
    }
    unsigned long long ts = now_ns();
    int nperm = 0, nop = 0;
    for (int i = 0; i < g_prev.n; i++) {
        const char *cat = pw_category(g_prev.f[i].key);
        if (!strcmp(cat, "permission")) nperm++;
        else if (!strcmp(cat, "appop")) nop++;
        if (g_mc->sink) {
            g_mc->sink->jb.len = 0;
            mod_emit_perm_change(&g_mc->sink->jb, ts, g_pkg, g_prev.f[i].key,
                                 "baseline", NULL, g_prev.f[i].val);
            anubee_sink_emit(g_mc->sink);
        }
    }
    if (!g_mc->quiet) {
        printf("[perm-watch] %s baseline: %d permission(s) granted, %d app-op(s)",
               g_pkg, nperm, nop);
        int special = 0;
        for (int i = 0; i < g_prev.n; i++) {
            const char *cat = pw_category(g_prev.f[i].key);
            if (!strcmp(cat, "permission") || !strcmp(cat, "appop") ||
                !strcmp(g_prev.f[i].key, "installed"))
                continue;
            printf("%s %s", special++ ? "," : "; special access:", g_prev.f[i].key);
        }
        printf("\n");
        if (g_mc->verbose)
            for (int i = 0; i < g_prev.n; i++)
                printf("[perm-watch]   %s = %s\n", g_prev.f[i].key, g_prev.f[i].val);
    }
    if (g_prev.truncated)
        fprintf(stderr, "mod perm-watch: more than %d facts; extra ones not tracked\n",
                PW_FACTS_MAX);

    g_stop = 0;
    if (pthread_create(&g_thread, NULL, poll_loop, NULL) != 0) {
        fprintf(stderr, "mod perm-watch: cannot start poll thread\n");
        pw_teardown();
        return NULL;
    }
    g_thread_running = 1;
    return g_rb;
}

static void pw_teardown(void)
{
    if (g_thread_running) {
        g_stop = 1;
        pthread_join(g_thread, NULL);
        g_thread_running = 0;
    }
    if (g_mc) pw_tick();   // thread joined: flush what it queued last
    if (g_rb) { ring_buffer__free(g_rb); g_rb = NULL; }
    if (g_stub_fd >= 0) { close(g_stub_fd); g_stub_fd = -1; }
}

static void pw_print_summary(void)
{
    if (!g_pkg) { printf("[perm-watch] --- inactive (no package resolved)\n"); return; }
    printf("[perm-watch] --- %s: %lu granted, %lu revoked, %lu changed",
           g_pkg, g_granted, g_revoked, g_changed);
    if (g_snap_failed) printf(" (%lu snapshot(s) failed, skipped)", g_snap_failed);
    printf("\n");
}

// Changes lost to a full hand-off queue -- reported like ring drops so the
// coverage record never claims full coverage over a gap.
static unsigned long long pw_drops(void)
{
    return g_q_dropped;
}

static const char *pw_inactive(void)
{
    return g_pkg ? NULL : "inactive: no package name resolved for the target";
}

const anubee_analyzer_t analyzer_perm_watch = {
    .name          = "perm-watch",
    .description   = "Baseline + timeline of the package's permissions, app-op modes, "
                     "Accessibility/notification-listener/device-admin enablement and "
                     "roles (stealthy -- shell polling every 2s, no BPF program)",
    .setup         = pw_setup,
    .teardown      = pw_teardown,
    .print_summary = pw_print_summary,
    .drops         = pw_drops,
    .tick          = pw_tick,
    .inactive      = pw_inactive,
};
