// SPDX-License-Identifier: GPL-2.0
// `ares mod fileless-detect` — userspace analyzer for the anonymous-
// executable-mapping signal. Owns the fileless_detect BPF skeleton lifecycle;
// the dispatcher in mod.c drives the poll loop and teardown order. Kernel
// side: src/modules/fileless_detect.bpf.c.
//
// Revision 1: detection is no longer ringbuf-driven. do_mmap
// entry/return writes a candidate into pending_map; __arm64_sys_prctl
// deletes (suppresses) it if ART's own dalvik- naming follows shortly
// after. This file owns the other half: a background thread that polls
// pending_map on a short interval and, for any entry that survives
// FILELESS_DETECT_GRACE_NS unsuppressed, builds a struct fileless_detect_event and
// emits it through the existing mod_emit_fileless_detect()/console-line path
// -- unchanged from before this revision. events_rb/the ring buffer
// ares_analyzer_t.setup() must return exists only to satisfy that
// interface; it carries no traffic for this analyzer.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fileless_detect.skel.h"
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
static pthread_mutex_t  fileless_stat_lock = PTHREAD_MUTEX_INITIALIZER;

static void fileless_stat_add(__u32 pid, const char *comm)
{
    pthread_mutex_lock(&fileless_stat_lock);
    for (int i = 0; i < fileless_stat_count; i++) {
        if (fileless_stats[i].pid == pid) {
            fileless_stats[i].count++;
            pthread_mutex_unlock(&fileless_stat_lock);
            return;
        }
    }
    if (fileless_stat_count < FILELESS_STAT_MAX) {
        fileless_stats[fileless_stat_count].pid = pid;
        snprintf(fileless_stats[fileless_stat_count].comm, TASK_COMM_LEN, "%s", comm);
        fileless_stats[fileless_stat_count].count = 1;
        fileless_stat_count++;
    }
    pthread_mutex_unlock(&fileless_stat_lock);
}

static struct fileless_detect_bpf *g_skel = NULL;
static struct bpf_link          *fileless_ff = NULL;
static struct ring_buffer       *g_rb = NULL;
static struct bpf_link          *mmap_entry_link = NULL;
static struct bpf_link          *mmap_ret_link = NULL;
static struct bpf_link          *prctl_link = NULL;
static struct ares_mod_ctx      *g_mc = NULL;

// ── grace-window background thread ──────────────────────────────────────
// Polls pending_map every FILELESS_POLL_MS; any entry older than
// FILELESS_DETECT_GRACE_NS that's still present (never suppressed by a
// dalvik-tagged prctl) graduates into an alert.

#define FILELESS_POLL_MS 100

static pthread_t g_poll_thread;
static volatile int g_poll_stop = 0;
static int g_poll_thread_running = 0;

static void fileless_emit_one(__u32 pid, __u64 addr, __u64 size, __u64 ts_ns, const char *comm)
{
    struct fileless_detect_event e = {0};
    e.h.type = MOD_EV_FILELESS_DETECT;
    e.h.pid  = pid;
    e.h.tid  = pid;
    e.ts_ns  = ts_ns;
    e.start  = addr;
    e.size   = size;
    snprintf(e.comm, TASK_COMM_LEN, "%s", comm);

    fileless_stat_add(pid, comm);

    if (!g_mc->quiet) {
        printf("[fileless-detect] PID:%-6d (%s) anonymous executable mmap, %llu bytes\n",
               pid, comm, (unsigned long long)size);
    }
    if (g_mc->sink != NULL) {
        mod_emit_fileless_detect(&g_mc->sink->jb, &e);
        ares_sink_emit(g_mc->sink);
    }
}

static __u64 fileless_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   // matches bpf_ktime_get_ns()'s clock base
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void *fileless_poll_loop(void *arg)
{
    (void)arg;
    int map_fd = bpf_map__fd(g_skel->maps.pending_map);

    while (!g_poll_stop) {
        usleep(FILELESS_POLL_MS * 1000);

        struct fileless_pending_key key = {0}, next_key;
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            struct fileless_pending_val val;
            if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0 &&
                fileless_now_ns() - val.ts_ns >= FILELESS_DETECT_GRACE_NS) {
                fileless_emit_one(next_key.pid, next_key.addr, val.size, val.ts_ns, val.comm);
                bpf_map_delete_elem(map_fd, &next_key);
                // A delete mutates the map's iteration order; restart the
                // walk from the beginning rather than continuing from a
                // now-stale key. Cheap: max_entries is 1024, polled every
                // FILELESS_POLL_MS.
                key = (struct fileless_pending_key){0};
                continue;
            }
            key = next_key;
        }
    }
    return NULL;
}

// ---- ring-buffer callback ---------------------------------------------------
// Unused: detection no longer flows through events_rb (see Revision 1 note
// above). Kept only because ring_buffer__new() requires a non-NULL sample
// callback and ares_analyzer_t.setup() must return a non-NULL ring_buffer*
// for the dispatcher's poll loop.

static int fileless_handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)data; (void)sz;
    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *fileless_setup(int uid, struct ares_mod_ctx *mc)
{
    g_mc = mc;

    g_skel = fileless_detect_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod fileless-detect: failed to open BPF skeleton\n");
        return NULL;
    }
    if (fileless_detect_bpf__load(g_skel)) {
        fprintf(stderr, "mod fileless-detect: failed to load BPF\n");
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

    mmap_entry_link = bpf_program__attach(g_skel->progs.on_do_mmap_entry);
    if (!mmap_entry_link) {
        fprintf(stderr, "mod fileless-detect: kprobe/do_mmap unavailable, aborting\n");
        goto err;
    }
    mmap_ret_link = bpf_program__attach(g_skel->progs.on_do_mmap_exit);
    if (!mmap_ret_link) {
        fprintf(stderr, "mod fileless-detect: kretprobe/do_mmap unavailable, aborting\n");
        goto err;
    }
    prctl_link = bpf_program__attach(g_skel->progs.on_prctl);
    if (!prctl_link) {
        fprintf(stderr, "mod fileless-detect: kprobe/__arm64_sys_prctl unavailable, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        fileless_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!fileless_ff) fprintf(stderr, "mod fileless-detect: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            fileless_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod fileless-detect: failed to create ring buffer\n");
        goto err;
    }

    g_poll_stop = 0;
    if (pthread_create(&g_poll_thread, NULL, fileless_poll_loop, NULL) != 0) {
        fprintf(stderr, "mod fileless-detect: failed to start grace-window poll thread\n");
        goto err;
    }
    g_poll_thread_running = 1;

    return g_rb;

err:
    if (mmap_entry_link) { bpf_link__destroy(mmap_entry_link); mmap_entry_link = NULL; }
    if (mmap_ret_link)   { bpf_link__destroy(mmap_ret_link);   mmap_ret_link   = NULL; }
    if (prctl_link)      { bpf_link__destroy(prctl_link);      prctl_link      = NULL; }
    if (fileless_ff)     { bpf_link__destroy(fileless_ff);     fileless_ff     = NULL; }
    if (g_rb)            { ring_buffer__free(g_rb);            g_rb            = NULL; }
    if (g_skel)          { fileless_detect_bpf__destroy(g_skel); g_skel          = NULL; }
    return NULL;
}

static void fileless_teardown(void)
{
    if (g_poll_thread_running) {
        g_poll_stop = 1;
        pthread_join(g_poll_thread, NULL);
        g_poll_thread_running = 0;
    }

    if (mmap_entry_link) { bpf_link__destroy(mmap_entry_link); mmap_entry_link = NULL; }
    if (mmap_ret_link)   { bpf_link__destroy(mmap_ret_link);   mmap_ret_link   = NULL; }
    if (prctl_link)      { bpf_link__destroy(prctl_link);      prctl_link      = NULL; }
    if (fileless_ff)     { bpf_link__destroy(fileless_ff);     fileless_ff     = NULL; }
    if (g_rb)            { ring_buffer__free(g_rb);            g_rb            = NULL; }
    if (g_skel)          { fileless_detect_bpf__destroy(g_skel); g_skel          = NULL; }
}

// ---- summary ----------------------------------------------------------------
// Lock-free reads of fileless_stats/fileless_stat_count are safe here
// only because mod.c always calls teardown() (joining the poll thread)
// before print_summary() or emit_summary(); changing that call order would
// require adding lock protection to these functions.

static void fileless_print_summary(void)
{
    if (fileless_stat_count == 0) return;

    printf("[fileless-detect] --- Fileless Detection Summary ---------------------------\n");
    printf("[fileless-detect]   PID     Comm             Count\n");
    for (int i = 0; i < fileless_stat_count; i++) {
        printf("[fileless-detect]  %6u  %-16s  %6u\n",
               fileless_stats[i].pid, fileless_stats[i].comm, fileless_stats[i].count);
    }
    printf("[fileless-detect]  %d process%s triggered an anonymous-exec mapping\n",
           fileless_stat_count, fileless_stat_count == 1 ? "" : "es");
}

static void fileless_emit_summary(struct ares_sink *s)
{
    if (fileless_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"fileless_detect_summary\"");
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

const ares_analyzer_t analyzer_fileless_detect = {
    .name          = "fileless-detect",
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
