// SPDX-License-Identifier: GPL-2.0
// `ares mod file-access` — userspace analyzer for sensitive openat/openat2
// events. Owns the file_access BPF skeleton lifecycle; the dispatcher in
// mod.c drives the poll loop and teardown order. Kernel side:
// src/modules/file_access.bpf.c. Classification: src/modules/file_access_classify.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_access.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/file_access_classify.h"

// ── per-path tally (tallied unconditionally so summary survives -o) ─────────

#define FA_STAT_MAX 512

typedef struct {
    char     path[FILE_PATH_LEN];
    uint32_t count;
    unsigned categories;
} fa_stat_t;

static fa_stat_t fa_stats[FA_STAT_MAX];
static int       fa_stat_count = 0;

static void fa_stat_add(const char *path, unsigned categories)
{
    for (int i = 0; i < fa_stat_count; i++) {
        if (strcmp(fa_stats[i].path, path) == 0) {
            fa_stats[i].count++;
            return;
        }
    }
    if (fa_stat_count >= FA_STAT_MAX) return;
    snprintf(fa_stats[fa_stat_count].path, sizeof(fa_stats[0].path), "%s", path);
    fa_stats[fa_stat_count].count = 1;
    fa_stats[fa_stat_count].categories = categories;
    fa_stat_count++;
}

static int fa_stat_cmp_desc(const void *a, const void *b)
{
    uint32_t ca = ((const fa_stat_t *)a)->count;
    uint32_t cb = ((const fa_stat_t *)b)->count;
    return (ca > cb) ? -1 : (ca < cb) ? 1 : 0;
}

// Single short tag for the console line; priority = most-specific signal first.
static const char *cat_tag(unsigned categories)
{
    if (categories & FA_FOREIGN_APP_DIR)    return "[foreign]";
    if (categories & FA_UNKNOWN_SELF)       return "[data?]";
    if (categories & FA_CREDENTIAL_PATTERN) return "[cred]";
    if (categories & FA_MEDIA_SUBDIR)       return "[media]";
    if (categories & FA_EXTERNAL_STORAGE)   return "[ext]";
    return "";
}

static struct file_access_bpf *g_skel       = NULL;
static struct bpf_link        *fa_ff        = NULL;
static struct ring_buffer     *g_rb         = NULL;
static struct bpf_link        *openat_link  = NULL;
static struct bpf_link        *openat2_link = NULL;

// ---- ring-buffer callback ---------------------------------------------------

static int fa_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_FILE_ACCESS || sz < sizeof(struct file_access_event))
        return 0;

    const struct file_access_event *e = data;
    unsigned categories = classify_path(e->path, mc->pkg);
    fa_stat_add(e->path, categories);

    const char *flag_strs[8];
    int n_flags = file_access_decode_flags(e->flags, flag_strs, 8);

    if (!mc->quiet) {
        printf("[file] %-9s PID:%-6d (%s) %s\n",
               cat_tag(categories), e->h.pid, e->comm, e->path);
    }

    if (mc->sink != NULL) {
        mod_emit_file_access(&mc->sink->jb, e, categories, flag_strs, n_flags);
        ares_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *fa_setup(int uid, struct ares_mod_ctx *mc)
{
    g_skel = file_access_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod file-access: failed to open BPF skeleton\n");
        return NULL;
    }
    if (file_access_bpf__load(g_skel)) {
        fprintf(stderr, "mod file-access: failed to load BPF\n");
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

    openat_link  = bpf_program__attach(g_skel->progs.on_openat);
    openat2_link = bpf_program__attach(g_skel->progs.on_openat2);

    if (!openat_link)
        fprintf(stderr, "mod file-access: kprobe/__arm64_sys_openat unavailable\n");
    if (!openat2_link)
        fprintf(stderr, "mod file-access: kprobe/__arm64_sys_openat2 unavailable (non-fatal)\n");

    if (!openat_link && !openat2_link) {
        fprintf(stderr, "mod file-access: no openat kprobe attached, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        fa_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!fa_ff) fprintf(stderr, "mod file-access: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            fa_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod file-access: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (fa_ff)         { bpf_link__destroy(fa_ff);         fa_ff         = NULL; }
    if (openat_link)   { bpf_link__destroy(openat_link);   openat_link   = NULL; }
    if (openat2_link)  { bpf_link__destroy(openat2_link);  openat2_link  = NULL; }
    if (g_skel)        { file_access_bpf__destroy(g_skel); g_skel        = NULL; }
    return NULL;
}

static void fa_teardown(void)
{
    if (fa_ff)         { bpf_link__destroy(fa_ff);         fa_ff         = NULL; }
    if (openat_link)   { bpf_link__destroy(openat_link);   openat_link   = NULL; }
    if (openat2_link)  { bpf_link__destroy(openat2_link);  openat2_link  = NULL; }
    if (g_rb)          { ring_buffer__free(g_rb);          g_rb          = NULL; }
    if (g_skel)        { file_access_bpf__destroy(g_skel); g_skel        = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void fa_print_summary(void)
{
    if (fa_stat_count == 0) return;

    qsort(fa_stats, fa_stat_count, sizeof(fa_stat_t), fa_stat_cmp_desc);

    uint64_t total = 0;
    int flagged = 0;
    for (int i = 0; i < fa_stat_count; i++) {
        total += fa_stats[i].count;
        if (fa_stats[i].categories) flagged++;
    }

    printf("[file] --- File Access Summary ---------------------------------\n");
    printf("[file]       Count  Tag        Path\n");
    for (int i = 0; i < fa_stat_count; i++) {
        printf("[file]  %6u  %-9s  %s\n",
               fa_stats[i].count, cat_tag(fa_stats[i].categories), fa_stats[i].path);
    }
    printf("[file]  %llu access%s across %d unique path%s (%d flagged)\n",
           (unsigned long long)total, total == 1 ? "" : "es",
           fa_stat_count, fa_stat_count == 1 ? "" : "s",
           flagged);
}

// File twin of fa_print_summary: same tally, one {"type":"file_access_summary",...}
// record. Reuses the FA_* category names from mod_emit_file_access's tag table
// (modules/mod_emit.c) so file and per-event records share one category
// vocabulary. fa_stats is already sorted by fa_print_summary before this runs.
static void fa_emit_summary(struct ares_sink *s)
{
    if (fa_stat_count == 0) return;

    uint64_t total = 0;
    int flagged = 0;
    for (int i = 0; i < fa_stat_count; i++) {
        total += fa_stats[i].count;
        if (fa_stats[i].categories) flagged++;
    }

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"file_access_summary\"");
    jb_s(j, ",\"total\":");       jb_u64(j, total);
    jb_s(j, ",\"unique_paths\":"); jb_u64(j, (unsigned long long)fa_stat_count);
    jb_s(j, ",\"flagged\":");     jb_u64(j, (unsigned long long)flagged);
    jb_s(j, ",\"paths\":[");
    struct { unsigned bit; const char *name; } tags[] = {
        { FA_EXTERNAL_STORAGE,   "external_storage"   },
        { FA_MEDIA_SUBDIR,       "media_subdir"       },
        { FA_CREDENTIAL_PATTERN, "credential_pattern" },
        { FA_FOREIGN_APP_DIR,    "foreign_app_dir"    },
        { FA_UNKNOWN_SELF,       "unknown_self"       },
    };
    for (int i = 0; i < fa_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"path\":\"");  jb_esc(j, fa_stats[i].path); jb_c(j, '"');
        jb_s(j, ",\"count\":");   jb_u64(j, fa_stats[i].count);
        jb_s(j, ",\"categories\":[");
        int first = 1;
        for (size_t t = 0; t < sizeof(tags) / sizeof(tags[0]); t++) {
            if (!(fa_stats[i].categories & tags[t].bit)) continue;
            if (!first) jb_c(j, ',');
            first = 0;
            jb_c(j, '"'); jb_s(j, tags[t].name); jb_c(j, '"');
        }
        jb_s(j, "]}");
    }
    jb_c(j, ']');
    jb_c(j, '}');
    ares_sink_emit(s);
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_file_access = {
    .name          = "file-access",
    .description   = "Trace sensitive file opens: external storage, credential-shaped "
                      "filenames, foreign app data dirs (stealthy — kprobes, zero uprobes)",
    .setup         = fa_setup,
    .teardown      = fa_teardown,
    .print_summary = fa_print_summary,
    .emit_summary  = fa_emit_summary,
};
