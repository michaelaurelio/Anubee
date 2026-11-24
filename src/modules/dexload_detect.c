// SPDX-License-Identifier: GPL-2.0
// `anubee mod dexload-detect` — payloads the traced app drops and loads:
// a DEX/CDEX/ZIP(APK/JAR)/ELF header written to a file (drop), that file
// being mapped by any process (load) and unlinked (delete), and a DEX ART
// holds only in memory (memload: InMemoryDexClassLoader, or a dex extracted
// from an app-writable archive). A copy of each payload is saved, with its
// SHA-256, so a "load then delete" dropper or a never-written DEX still
// leaves the second stage behind. Kernel side: src/modules/dexload_detect.bpf.c.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "dexload_detect.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/dexload_detect_parse.h"
#include "modules/payload_store.h"
#include "modules/fileless_detect_parse.h"   // fl_maps_region
#include "common/proc_mem.h"

_Static_assert(DL_COMP_LEN == DEXLOAD_COMP_LEN, "path component size mismatch");

#define DL_FILE_MAX  256
#define DL_SAVE_MAX  (256LL * 1024 * 1024)   // skip saving anything larger

typedef struct {
    __u64              ino;
    __u32              dev;
    __u32              pid;                 // dropper
    char               comm[TASK_COMM_LEN];
    int                kind;
    char               path[512];
    unsigned long long drop_ts_ns;
    int                loaded, exec, deleted;
    int                memload;             // DEX held in memory, no file
    __u32              loader_pid;          // last process that mapped it
    char               saved[512];          // empty = no copy yet
    char               sha256[65];
    long long          size;
} dl_file_t;

static dl_file_t dl_files[DL_FILE_MAX];
static int       dl_file_count = 0;
static unsigned  dl_files_lost = 0;         // drops past DL_FILE_MAX

static struct dexload_detect_bpf *g_skel = NULL;
static struct ring_buffer        *g_rb = NULL;
static struct bpf_link           *g_links[6];
static int                        g_nlinks = 0;

static dl_file_t *dl_find(__u64 ino, __u32 dev)
{
    for (int i = 0; i < dl_file_count; i++)
        if (dl_files[i].ino && dl_files[i].ino == ino && dl_files[i].dev == dev)
            return &dl_files[i];
    return NULL;
}

// ---- saving a payload copy ---------------------------------------------------

static void dl_save(dl_file_t *f, __u32 pid)
{
    if (f->saved[0] || !payload_dir_ready()) return;
    int fd = payload_open_ino(f->path, pid, f->ino);
    if (fd < 0 && pid != f->pid) fd = payload_open_ino(f->path, f->pid, f->ino);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > DL_SAVE_MAX) { close(fd); return; }
    char dst[512];
    dl_payload_name(dst, sizeof dst, payload_dir(), f->pid, f->ino, f->kind);
    long long n = dl_copy_fd(fd, dst, f->sha256);
    close(fd);
    if (n <= 0) { unlink(dst); return; }
    snprintf(f->saved, sizeof f->saved, "%s", dst);
    f->size = n;
}

// ---- memload: DEX held in anonymous memory -------------------------------------
// ART names the region before copying the DEX in, so the read is deferred to
// the dispatcher tick and retried until the header is valid.

#define DL_MEM_MAX       64
#define DL_MEM_RETRY_NS  (2000ULL * 1000000ULL)
#define DL_MEM_POLL_NS   (100ULL * 1000000ULL)

typedef struct {
    struct dexload_detect_event e;   // the kernel event (addr, len, comm, ts)
    unsigned long long          seen_ns;
} dl_mem_t;

static dl_mem_t dl_mem[DL_MEM_MAX];
static int      dl_mem_count = 0;
static unsigned dl_mem_lost = 0;
static struct anubee_mod_ctx *g_mc = NULL;

static unsigned long long dl_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static void dl_mem_queue(const struct dexload_detect_event *e)
{
    if (dl_mem_count >= DL_MEM_MAX) { dl_mem_lost++; return; }
    dl_mem[dl_mem_count].e = *e;
    dl_mem[dl_mem_count].seen_ns = dl_now_ns();
    dl_mem_count++;
}

// Full region name from /proc/<pid>/maps (the kernel event holds only the
// first DEXLOAD_COMP_LEN bytes). 0 if the region is gone.
static int dl_mem_region_name(__u32 pid, __u64 addr, char *name, size_t cap)
{
    static char maps[1 << 20];
    char p[64];
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

static void dl_mem_report(dl_mem_t *m, const char *source, const char *saved,
                          const char *sha, long long size)
{
    struct dexload_detect_event *e = &m->e;
    if (dl_file_count < DL_FILE_MAX) {
        dl_file_t *f = &dl_files[dl_file_count++];
        memset(f, 0, sizeof *f);
        f->pid = e->h.pid;
        snprintf(f->comm, sizeof f->comm, "%s", e->comm);
        f->kind = DL_DEX;
        if (source) snprintf(f->path, sizeof f->path, "%s", source);
        else        snprintf(f->path, sizeof f->path, "(memory %#llx)", (unsigned long long)e->addr);
        f->drop_ts_ns = e->ts_ns;
        f->loaded = 1;
        f->memload = 1;
        if (saved) {
            snprintf(f->saved, sizeof f->saved, "%s", saved);
            snprintf(f->sha256, sizeof f->sha256, "%s", sha);
            f->size = size;
        } else {
            f->size = -1;
        }
    } else {
        dl_files_lost++;
    }

    if (!g_mc->quiet) {
        printf("[dexload-detect] PID:%-6d (%s) memload dex  %s %#llx (%llu bytes)\n",
               e->h.pid, e->comm, source ? source : "[from memory]",
               (unsigned long long)e->addr, (unsigned long long)e->len);
        if (saved)
            printf("[dexload-detect]   saved %s (%lld bytes, sha256 %s)\n", saved, size, sha);
        else
            printf("[dexload-detect]   no valid DEX header readable in the region -- not saved\n");
    }
    if (g_mc->sink) {
        mod_emit_dexload_detect(&g_mc->sink->jb, e, "dex", source, -1, saved, sha, size);
        anubee_sink_emit(g_mc->sink);
    }
}

// 1 = finished with this entry (reported or dropped), 0 = retry later.
static int dl_mem_try(dl_mem_t *m, int final)
{
    struct dexload_detect_event *e = &m->e;
    char name[512];
    if (!dl_mem_region_name(e->h.pid, e->addr, name, sizeof name))
        return 1;                                 // unmapped already, or process gone
    const char *source = NULL;
    if (!dl_memload_wanted(name, &source))
        return 1;                                 // the platform's own code

    unsigned char h[0x70];
    unsigned fs = 0;
    int mem = proc_mem_open((int)e->h.pid);
    size_t got = mem >= 0 ? proc_mem_read(mem, e->addr, h, sizeof h) : 0;
    if (mem >= 0) close(mem);
    if (!dl_dex_header_ok(h, got, (unsigned long)e->len, &fs)) {
        if (!final && dl_now_ns() - m->seen_ns < DL_MEM_RETRY_NS)
            return 0;                             // not copied in yet
        dl_mem_report(m, source, NULL, NULL, -1);
        return 1;
    }

    char dst[512] = "", sha[65] = "";
    long long n = -1;
    if (payload_dir_ready()) {
        snprintf(dst, sizeof dst, "%s/%u-mem-%llx.dex", payload_dir(), e->h.pid,
                 (unsigned long long)e->addr);
        n = payload_save_region(e->h.pid, (unsigned long)e->addr, fs, dst, sha, NULL, 0, NULL);
        if (n != (long long)fs) { unlink(dst); n = -1; }
    }
    dl_mem_report(m, source, n > 0 ? dst : NULL, sha, n);
    return 1;
}

static void dl_mem_pass(int final)
{
    for (int i = 0; i < dl_mem_count; ) {
        if (dl_mem_try(&dl_mem[i], final)) {
            dl_mem[i] = dl_mem[--dl_mem_count];
            continue;
        }
        i++;
    }
}

static void dl_tick(void)
{
    static unsigned long long last;
    unsigned long long now = dl_now_ns();
    if (!dl_mem_count || now - last < DL_MEM_POLL_NS) return;
    last = now;
    dl_mem_pass(0);
}

// ---- ring-buffer callback ------------------------------------------------------

static int dl_handle_event(void *ctx, void *data, size_t sz)
{
    struct anubee_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;
    if (hdr->type != MOD_EV_DEXLOAD_DETECT || sz < sizeof(struct dexload_detect_event))
        return 0;
    const struct dexload_detect_event *e = data;

    if (e->stage == DEXLOAD_STAGE_MEMLOAD) {
        dl_mem_queue(e);
        return 0;
    }

    dl_file_t *f = dl_find(e->ino, e->dev);
    char path[512] = "";
    if (e->ncomp)
        dl_path_join(&e->comp[0][0], e->ncomp, DEXLOAD_COMP_LEN, e->truncated, path, sizeof path);

    int alert = 1, just_saved = 0;
    long long after_ms = -1;
    if (e->stage == DEXLOAD_STAGE_DROP) {
        int kind = dl_kind_of(e->head, sizeof e->head);
        if (kind == DL_NONE) return 0;          // "dex\n" without a version, etc.
        if (!f) {
            if (dl_file_count >= DL_FILE_MAX) { dl_files_lost++; return 0; }
            f = &dl_files[dl_file_count++];
        }
        memset(f, 0, sizeof *f);                // also a reused inode after delete
        f->ino = e->ino;
        f->dev = e->dev;
        f->pid = e->h.pid;
        snprintf(f->comm, sizeof f->comm, "%s", e->comm);
        f->kind = kind;
        snprintf(f->path, sizeof f->path, "%s", path);
        f->drop_ts_ns = e->ts_ns;
        f->size = -1;
        alert = dl_drop_alerts(kind) || mc->verbose;
    } else {
        if (!f) return 0;                       // drop not recognised by userspace
        after_ms = (long long)((e->ts_ns - f->drop_ts_ns) / 1000000ULL);
        if (e->stage == DEXLOAD_STAGE_LOAD) {
            f->loaded = 1;
            f->exec |= e->exec;
            f->loader_pid = e->h.pid;
            if (path[0]) snprintf(f->path, sizeof f->path, "%s", path);   // follow renames
        } else {
            f->deleted = 1;
        }
        int had_copy = f->saved[0] != 0;
        dl_save(f, e->h.pid);
        just_saved = !had_copy && f->saved[0];
    }

    if (alert && !mc->quiet) {
        static const char *const verb[] = { "?", "dropped", "loaded", "deleted" };
        printf("[dexload-detect] PID:%-6d (%s) %-7s %-4s %s", e->h.pid, e->comm,
               verb[e->stage <= DEXLOAD_STAGE_DELETE ? e->stage : 0],
               dl_kind_name(f->kind), f->path[0] ? f->path : "?");
        if (e->stage == DEXLOAD_STAGE_LOAD && e->exec) printf(" [exec]");
        if (after_ms >= 0) printf(" (%lldms after drop)", after_ms);
        printf("\n");
        if (just_saved)
            printf("[dexload-detect]   saved %s (%lld bytes, sha256 %s)\n",
                   f->saved, f->size, f->sha256);
    }

    if (mc->sink) {
        mod_emit_dexload_detect(&mc->sink->jb, e, dl_kind_name(f->kind),
                                f->path[0] ? f->path : NULL, after_ms,
                                f->saved[0] ? f->saved : NULL, f->sha256, f->size);
        anubee_sink_emit(mc->sink);
    }
    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------------

static void dl_teardown(void);

static struct ring_buffer *dl_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_mc = mc;
    payload_dir_init(mc->sink ? mc->sink->path : NULL);

    g_skel = dexload_detect_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod dexload-detect: failed to open BPF skeleton\n");
        return NULL;
    }
    if (dexload_detect_bpf__load(g_skel)) {
        fprintf(stderr, "mod dexload-detect: failed to load BPF\n");
        goto err;
    }

    __u8 one = 1;
    if (uid > 0) {
        __u32 u = (__u32)uid;
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_uids), &u, &one, BPF_ANY);
    }
    if (mc->tgt && mc->tgt->n > 0)
        for (int i = 0; i < mc->tgt->n; i++) {
            __u32 tgid = (__u32)mc->tgt->pids[i];
            bpf_map_update_elem(bpf_map__fd(g_skel->maps.target_pids), &tgid, &one, BPF_ANY);
        }

    struct bpf_program *progs[] = {
        g_skel->progs.on_vfs_write, g_skel->progs.on_mmap_file, g_skel->progs.on_inode_unlink,
        g_skel->progs.on_prctl,
    };
    for (unsigned i = 0; i < sizeof progs / sizeof progs[0]; i++) {
        struct bpf_link *l = bpf_program__attach(progs[i]);
        if (!l) {
            fprintf(stderr, "mod dexload-detect: attaching %s failed (%s), aborting\n",
                    bpf_program__name(progs[i]), strerror(errno));
            goto err;
        }
        g_links[g_nlinks++] = l;
    }
    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        struct bpf_link *l = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (l) g_links[g_nlinks++] = l;
        else fprintf(stderr, "mod dexload-detect: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb), dl_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod dexload-detect: failed to create ring buffer\n");
        goto err;
    }
    printf("[dexload-detect] payload copies go to %s\n", payload_dir());
    return g_rb;

err:
    dl_teardown();
    return NULL;
}

static void dl_teardown(void)
{
    while (g_nlinks > 0) bpf_link__destroy(g_links[--g_nlinks]);
    if (g_rb)   { ring_buffer__free(g_rb); g_rb = NULL; }
    if (g_skel) { dexload_detect_bpf__destroy(g_skel); g_skel = NULL; }
    // In-memory DEX still waiting for its header: one last try.
    if (g_mc) dl_mem_pass(1);
    // Payloads never loaded or deleted while we watched: the file is complete
    // by now, keep a copy for the summary.
    for (int i = 0; i < dl_file_count; i++)
        if (!dl_files[i].deleted && !dl_files[i].memload)
            dl_save(&dl_files[i], dl_files[i].loader_pid ? dl_files[i].loader_pid : dl_files[i].pid);
}

// ---- summary ---------------------------------------------------------------------

static void dl_print_summary(void)
{
    if (dl_file_count == 0) return;
    printf("[dexload-detect] --- Payloads written or loaded by the app ---\n");
    for (int i = 0; i < dl_file_count; i++) {
        const dl_file_t *f = &dl_files[i];
        printf("[dexload-detect]  %6u  %-4s %s%s%s%s\n", f->pid, dl_kind_name(f->kind),
               f->path[0] ? f->path : "?",
               f->memload ? " [in memory]" : f->loaded ? (f->exec ? " [loaded, exec]" : " [loaded]") : "",
               f->deleted ? " [deleted]" : "", f->saved[0] ? "" : " [no copy]");
        if (f->saved[0])
            printf("[dexload-detect]          -> %s (%lld bytes, sha256 %s)\n",
                   f->saved, f->size, f->sha256);
    }
    if (dl_files_lost)
        printf("[dexload-detect]  %u more payload file%s not tracked (table full)\n",
               dl_files_lost, dl_files_lost == 1 ? "" : "s");
    if (dl_mem_lost)
        printf("[dexload-detect]  %u in-memory DEX region%s not examined (queue full)\n",
               dl_mem_lost, dl_mem_lost == 1 ? "" : "s");
}

static void dl_emit_summary(struct anubee_sink *s)
{
    if (dl_file_count == 0) return;
    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_s(j, "{\"type\":\"dexload_detect_summary\",\"file_count\":");
    jb_u64(j, (unsigned long long)dl_file_count);
    jb_s(j, ",\"untracked\":"); jb_u64(j, dl_files_lost + dl_mem_lost);
    jb_s(j, ",\"files\":[");
    for (int i = 0; i < dl_file_count; i++) {
        const dl_file_t *f = &dl_files[i];
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");      jb_u64(j, f->pid);
        jb_s(j, ",\"comm\":\"");   jb_esc(j, f->comm); jb_c(j, '"');
        jb_s(j, ",\"kind\":\"");   jb_s(j, dl_kind_name(f->kind)); jb_c(j, '"');
        jb_s(j, ",\"path\":\"");   jb_esc(j, f->path); jb_c(j, '"');
        jb_s(j, ",\"ino\":");      jb_u64(j, f->ino);
        jb_s(j, ",\"loaded\":");   jb_s(j, f->loaded ? "true" : "false");
        jb_s(j, ",\"exec\":");     jb_s(j, f->exec ? "true" : "false");
        jb_s(j, ",\"deleted\":");  jb_s(j, f->deleted ? "true" : "false");
        jb_s(j, ",\"memload\":");  jb_s(j, f->memload ? "true" : "false");
        jb_s(j, ",\"saved\":");
        if (f->saved[0]) {
            jb_s(j, "{\"file\":\""); jb_esc(j, f->saved);
            jb_s(j, "\",\"sha256\":\""); jb_s(j, f->sha256);
            jb_s(j, "\",\"size\":"); jb_u64(j, (unsigned long long)f->size);
            jb_c(j, '}');
        } else {
            jb_s(j, "null");
        }
        jb_c(j, '}');
    }
    jb_s(j, "]}");
    anubee_sink_emit(s);
}

static unsigned long long dl_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

const anubee_analyzer_t analyzer_dexload_detect = {
    .name          = "dexload-detect",
    .description   = "Payloads the app drops and loads: DEX/APK/JAR/ELF headers written to a "
                      "file, that file mapped (loaded) and deleted, and DEX loaded straight from "
                      "memory (InMemoryDexClassLoader), with a saved copy + SHA-256 of each "
                      "(dropper / DexClassLoader / native second stage; kprobes only, zero uprobes)",
    .setup         = dl_setup,
    .teardown      = dl_teardown,
    .print_summary = dl_print_summary,
    .emit_summary  = dl_emit_summary,
    .drops         = dl_drops,
    .tick          = dl_tick,
};
