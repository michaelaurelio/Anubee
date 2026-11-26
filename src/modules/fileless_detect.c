// SPDX-License-Identifier: GPL-2.0
// `anubee mod fileless-detect` — executable memory with no file behind it.
// Kernel side: src/modules/fileless_detect.bpf.c. Two paths in:
//   - anon_exec_mmap candidates sit in pending_map; the dispatcher tick
//     (the sink's single writer) graduates those older than
//     FILELESS_DETECT_GRACE_NS, reading each region's name from
//     /proc/<pid>/maps and dropping ART's own (fileless_detect_parse.c).
//   - mprotect_exec / memfd_exec arrive on the ring, ART already excluded by
//     name in the kernel.
// Each alert classifies the region's first bytes (elf / zero / data) and
// saves a copy -- the region through /proc/<pid>/mem, a memfd through its
// fd -- into the payload store, unless it is all zero.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "modules/fileless_detect_parse.h"
#include "modules/dexload_detect_parse.h"   // dl_copy_fd
#include "modules/payload_store.h"

#define FILELESS_STAT_MAX     64
#define FILELESS_SAVE_MAX     (64ULL * 1024 * 1024)   // larger regions aren't copied
#define FILELESS_SAVES_PER_PID 32                     // bound disk use per process
#define FILELESS_PRINT_PER_PID 10                     // console lines per process

typedef struct {
    __u32    pid;
    char     comm[TASK_COMM_LEN];
    uint32_t count;
    uint32_t by_kind[4];      // indexed by enum fl_kind
    uint32_t saved;
} fileless_stat_t;

static fileless_stat_t fileless_stats[FILELESS_STAT_MAX];
static int             fileless_stat_count = 0;

static fileless_stat_t *fileless_stat_get(__u32 pid, const char *comm)
{
    for (int i = 0; i < fileless_stat_count; i++)
        if (fileless_stats[i].pid == pid)
            return &fileless_stats[i];
    if (fileless_stat_count >= FILELESS_STAT_MAX) return NULL;
    fileless_stat_t *s = &fileless_stats[fileless_stat_count++];
    memset(s, 0, sizeof *s);
    s->pid = pid;
    snprintf(s->comm, TASK_COMM_LEN, "%s", comm);
    return s;
}

static struct fileless_detect_bpf *g_skel = NULL;
static struct ring_buffer        *g_rb = NULL;
static struct bpf_link           *g_links[5];
static int                        g_nlinks = 0;
static struct anubee_mod_ctx     *g_mc = NULL;

// ---- one alert: classify, save, print, emit ---------------------------------

static void fileless_report(struct fileless_detect_event *e)
{
    fileless_stat_t *st = fileless_stat_get(e->h.pid, e->comm);
    if (st) {
        st->count++;
        if (e->kind < 4) st->by_kind[e->kind]++;
    }

    // Save a copy and look at the first bytes.
    unsigned char head[16];
    size_t head_n = 0;
    char saved[512] = "", sha[65] = "";
    long long size = -1;
    int may_save = (!st || st->saved < FILELESS_SAVES_PER_PID) && payload_dir_ready();
    if (e->kind == FL_KIND_MEMFD_EXEC) {
        int fd = payload_open_ino(NULL, e->h.pid, e->ino);
        if (fd >= 0) {
            ssize_t r = pread(fd, head, sizeof head, 0);
            head_n = r > 0 ? (size_t)r : 0;
            if (may_save && e->size && e->size <= FILELESS_SAVE_MAX &&
                strcmp(fl_content_of(head, head_n) ? fl_content_of(head, head_n) : "zero", "zero")) {
                snprintf(saved, sizeof saved, "%s/%u-memfd-%llu.bin", payload_dir(), e->h.pid,
                         (unsigned long long)e->ino);
                lseek(fd, 0, SEEK_SET);
                size = dl_copy_fd(fd, saved, sha);
            }
            close(fd);
        }
    } else if (e->size && e->size <= FILELESS_SAVE_MAX && may_save) {
        snprintf(saved, sizeof saved, "%s/%u-%llx.bin", payload_dir(), e->h.pid,
                 (unsigned long long)e->start);
        int nonzero = 0;
        size = payload_save_region(e->h.pid, e->start, e->size, saved, sha, head, sizeof head,
                                   &nonzero);
        head_n = size > 0 ? (size_t)(size < (long long)sizeof head ? size : (long long)sizeof head) : 0;
        if (size <= 0 || !nonzero) {   // unreadable, or nothing written into it yet
            unlink(saved);
            saved[0] = '\0';
            size = -1;
        }
    }
    if (saved[0] && size > 0 && st) st->saved++;
    if (!saved[0]) size = -1;
    const char *content = fl_content_of(head, head_n);

    if (!g_mc->quiet && (!st || st->count <= FILELESS_PRINT_PER_PID)) {
        printf("[fileless-detect] PID:%-6d (%s) %-14s %#llx %llu bytes%s%s%s%s",
               e->h.pid, e->comm, fl_kind_name((int)e->kind),
               (unsigned long long)e->start, (unsigned long long)e->size,
               e->anon_name[0] ? " name=" : "", e->anon_name,
               content ? " content=" : "", content ? content : "");
        printf("\n");
        if (saved[0])
            printf("[fileless-detect]   saved %s (sha256 %s)\n", saved, sha);
        if (st && st->count == FILELESS_PRINT_PER_PID)
            printf("[fileless-detect]   (further alerts for PID %u counted, not printed)\n", e->h.pid);
    }
    if (g_mc->sink) {
        mod_emit_fileless_detect(&g_mc->sink->jb, e, fl_kind_name((int)e->kind), content,
                                 saved[0] ? saved : NULL, sha, size);
        anubee_sink_emit(g_mc->sink);
    }
}

// ---- anon_exec_mmap: grace-window graduation (dispatcher tick) -----------------

#define FILELESS_POLL_MS 100

static __u64 fileless_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   // matches bpf_ktime_get_ns()'s clock base
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

// The region's name as the kernel holds it now. Returns 0 if the address is
// no longer mapped (name left empty).
static int fileless_region_name(__u32 pid, __u64 addr, char *name, size_t cap)
{
    static char maps[1 << 20];
    char p[64];
    name[0] = '\0';
    snprintf(p, sizeof p, "/proc/%u/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    size_t n = fread(maps, 1, sizeof maps - 1, f);
    fclose(f);
    maps[n] = '\0';
    unsigned long s, e;
    char perms[8];
    return fl_maps_region(maps, (unsigned long)addr, &s, &e, perms, name, cap);
}

static void fileless_tick(void)
{
    static __u64 last_scan_ns;
    if (!g_skel)
        return;
    __u64 now = fileless_now_ns();
    if (now - last_scan_ns < FILELESS_POLL_MS * 1000000ULL)
        return;
    last_scan_ns = now;

    int map_fd = bpf_map__fd(g_skel->maps.pending_map);
    struct fileless_pending_key key = {0}, next_key;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        struct fileless_pending_val val;
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0 &&
            fileless_now_ns() - val.ts_ns >= FILELESS_DETECT_GRACE_NS) {
            char name[128];
            fileless_region_name(next_key.pid, next_key.addr, name, sizeof name);
            if (!fl_name_is_art(name)) {
                struct fileless_detect_event e = {0};
                e.h.type = MOD_EV_FILELESS_DETECT;
                e.h.pid  = next_key.pid;
                e.h.tid  = next_key.pid;
                e.ts_ns  = val.ts_ns;
                e.start  = next_key.addr;
                e.size   = val.size;
                e.kind   = FL_KIND_ANON_MMAP;
                snprintf(e.comm, TASK_COMM_LEN, "%s", val.comm);
                snprintf(e.anon_name, sizeof e.anon_name, "%s", name);
                fileless_report(&e);
            }
            bpf_map_delete_elem(map_fd, &next_key);
            // A delete changes the iteration order; restart from the top
            // (max_entries is 1024, scanned every FILELESS_POLL_MS).
            key = (struct fileless_pending_key){0};
            continue;
        }
        key = next_key;
    }
}

// ---- mprotect_exec / memfd_exec: ring callback ---------------------------------

static int fileless_handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    const struct trace_event_header *hdr = data;
    if (hdr->type != MOD_EV_FILELESS_DETECT || sz < sizeof(struct fileless_detect_event))
        return 0;
    struct fileless_detect_event e;
    memcpy(&e, data, sizeof e);
    e.anon_name[FILELESS_DETECT_TAG_LEN - 1] = '\0';
    fileless_report(&e);
    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static void fileless_teardown(void);

static struct ring_buffer *fileless_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_mc = mc;
    payload_dir_init(mc->sink ? mc->sink->path : NULL);

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

    struct bpf_program *progs[] = {
        g_skel->progs.on_do_mmap_entry, g_skel->progs.on_do_mmap_exit,
        g_skel->progs.on_mprotect, g_skel->progs.on_mmap_file,
    };
    for (unsigned i = 0; i < sizeof progs / sizeof progs[0]; i++) {
        struct bpf_link *l = bpf_program__attach(progs[i]);
        if (!l) {
            fprintf(stderr, "mod fileless-detect: attaching %s failed, aborting\n",
                    bpf_program__name(progs[i]));
            goto err;
        }
        g_links[g_nlinks++] = l;
    }
    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        struct bpf_link *l = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (l) g_links[g_nlinks++] = l;
        else fprintf(stderr, "mod fileless-detect: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            fileless_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod fileless-detect: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    fileless_teardown();
    return NULL;
}

static void fileless_teardown(void)
{
    while (g_nlinks > 0) bpf_link__destroy(g_links[--g_nlinks]);
    if (g_rb)   { ring_buffer__free(g_rb); g_rb = NULL; }
    if (g_skel) { fileless_detect_bpf__destroy(g_skel); g_skel = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void fileless_print_summary(void)
{
    if (fileless_stat_count == 0) return;

    printf("[fileless-detect] --- Executable memory without a file ---\n");
    for (int i = 0; i < fileless_stat_count; i++) {
        const fileless_stat_t *s = &fileless_stats[i];
        printf("[fileless-detect]  %6u  %-16s anon_exec_mmap=%u mprotect_exec=%u memfd_exec=%u saved=%u\n",
               s->pid, s->comm, s->by_kind[FL_KIND_ANON_MMAP], s->by_kind[FL_KIND_MPROTECT_EXEC],
               s->by_kind[FL_KIND_MEMFD_EXEC], s->saved);
    }
    printf("[fileless-detect]  %d process%s created executable memory without a file\n",
           fileless_stat_count, fileless_stat_count == 1 ? "" : "es");
}

static void fileless_emit_summary(struct anubee_sink *s)
{
    if (fileless_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"fileless_detect_summary\"");
    jb_s(j, ",\"process_count\":"); jb_u64(j, (unsigned long long)fileless_stat_count);
    jb_s(j, ",\"processes\":[");
    for (int i = 0; i < fileless_stat_count; i++) {
        const fileless_stat_t *st = &fileless_stats[i];
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");    jb_u64(j, st->pid);
        jb_s(j, ",\"comm\":\""); jb_esc(j, st->comm); jb_c(j, '"');
        jb_s(j, ",\"count\":");  jb_u64(j, st->count);
        for (int k = FL_KIND_ANON_MMAP; k <= FL_KIND_MEMFD_EXEC; k++) {
            jb_s(j, ",\""); jb_s(j, fl_kind_name(k)); jb_s(j, "\":");
            jb_u64(j, st->by_kind[k]);
        }
        jb_s(j, ",\"saved\":");  jb_u64(j, st->saved);
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    anubee_sink_emit(s);
}

static unsigned long long fileless_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const anubee_analyzer_t analyzer_fileless_detect = {
    .name          = "fileless-detect",
    .description   = "Executable memory with no file behind it: anonymous executable "
                      "mappings, memory made executable later (unpackers), and code run "
                      "from a memfd -- ART's own JIT regions excluded by name; first bytes "
                      "classified and a copy saved (stealthy -- kprobes only, zero uprobes)",
    .setup         = fileless_setup,
    .teardown      = fileless_teardown,
    .print_summary = fileless_print_summary,
    .emit_summary  = fileless_emit_summary,
    .drops         = fileless_drops,
    .tick          = fileless_tick,
};
