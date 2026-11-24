// SPDX-License-Identifier: GPL-2.0
// `anubee mod binder-api` — which Binder interfaces and methods the traced app
// calls: the Android-API view of its behavior (what it asks system_server /
// other services to do), below any Java-level obfuscation. Kernel side:
// src/modules/binder_api.bpf.c (kprobe on binder_transaction, first call per
// (process, interface, method) sent up, repeats counted in-kernel).
//
// Method names come from the device's own framework jars: every AIDL
// interface's generated `$Stub` class carries `TRANSACTION_<method> = code`
// constants (src/modules/binder_api_parse.c), so the table always matches
// the running Android build. Approach credit: WOOTdroid/WDBind (interface
// token + transaction code -> API method), reimplemented here.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "binder_api.skel.h"
#include "common/analyzer.h"
#include "common/emit.h"
#include "common/engine_args.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/binder_api_parse.h"
#include "modules/binder_names_load.h"

static struct binder_api_bpf *g_skel = NULL;
static struct bpf_link *g_link = NULL, *g_ff = NULL;
static struct ring_buffer *g_rb = NULL;
static struct anubee_mod_ctx *g_mc = NULL;

// ---- method-name table from framework jars ----------------------------------

static struct binder_names *g_names = NULL;
static int g_njar = 0;

// ---- token hash -> decoded name (for the summary) --------------------------

#define BA_TOK_MAX 1024
static struct { __u64 hash; char *tok; } g_tok[BA_TOK_MAX];
static int g_ntok = 0;

static const char *ba_tok_get(__u64 h)
{
    for (int i = 0; i < g_ntok; i++)
        if (g_tok[i].hash == h) return g_tok[i].tok;
    return NULL;
}

static void ba_tok_put(__u64 h, const char *tok)
{
    if (!h || ba_tok_get(h) || g_ntok == BA_TOK_MAX) return;
    char *d = strdup(tok);
    if (!d) return;
    g_tok[g_ntok].hash = h;
    g_tok[g_ntok++].tok = d;
}

// ---- content-provider access: (pid, method, detail) -> count -----------------

#define BA_CP_IFACE "android.content.IContentProvider"
#define BA_CP_MAX   2048
struct ba_cp { __u32 pid; char method[24]; char detail[400]; unsigned long count; };
static struct ba_cp *g_cp = NULL;
static int g_ncp = 0;
static unsigned long g_cp_overflow = 0;

static void ba_cp_detail_str(const struct binder_cp_detail *d, char *out, size_t outsz)
{
    if (d->uri[0])
        snprintf(out, outsz, "%s", d->uri);
    else if (d->authority[0])
        snprintf(out, outsz, "%s %s%s%s", d->authority, d->method,
                 d->arg[0] ? " " : "", d->arg);
    else
        out[0] = '\0';
}

// Returns 1 the first time (pid, method, detail) is seen.
static int ba_cp_note(__u32 pid, const char *method, const char *detail)
{
    for (int i = 0; i < g_ncp; i++)
        if (g_cp[i].pid == pid && !strcmp(g_cp[i].method, method) &&
            !strcmp(g_cp[i].detail, detail)) {
            g_cp[i].count++;
            return 0;
        }
    if (!g_cp) g_cp = calloc(BA_CP_MAX, sizeof *g_cp);
    if (!g_cp || g_ncp == BA_CP_MAX) { g_cp_overflow++; return 1; }
    struct ba_cp *c = &g_cp[g_ncp++];
    c->pid = pid;
    snprintf(c->method, sizeof c->method, "%s", method);
    snprintf(c->detail, sizeof c->detail, "%s", detail);
    c->count = 1;
    return 1;
}

// ---- events -------------------------------------------------------------------

static unsigned long g_first_seen = 0, g_unnamed = 0, g_no_token = 0;

static int ba_handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct binder_api_event)) return 0;
    const struct binder_api_event *e = data;
    size_t n = e->raw_len < BINDER_API_RAW ? e->raw_len : BINDER_API_RAW;

    char tok[160];
    const char *iface = NULL, *method = NULL;
    if (binder_parcel_token(e->raw, n, tok, sizeof tok) > 0) {
        iface = tok;
        ba_tok_put(e->token_hash, tok);
        method = binder_names_lookup(g_names, tok, e->code);
        if (!method) g_unnamed++;
    } else {
        g_no_token++;
    }
    // IContentProvider is reported on every call (binder_api_always): pull out
    // the URI or CALL target, and print each distinct one once.
    struct binder_cp_detail cp, *cpp = NULL;
    int print = 1;
    if (iface && !strcmp(iface, BA_CP_IFACE) &&
        binder_cp_describe(e->raw, n, method && !strcmp(method, "CALL"), &cp)) {
        cpp = &cp;
        char det[400];
        ba_cp_detail_str(&cp, det, sizeof det);
        print = ba_cp_note(e->h.pid, method ? method : "?", det);
    } else if (iface && !strcmp(iface, BA_CP_IFACE)) {
        print = ba_cp_note(e->h.pid, method ? method : "?", "");
    }
    if (print) g_first_seen++;

    if (!g_mc->quiet && print) {
        printf("[binder-api] PID:%-6u (%s) %s.%s", e->h.pid, e->comm,
               iface ? iface : "<no-token>", method ? method : "");
        if (!method) printf("#%u", e->code);
        if (cpp) {
            char det[400];
            ba_cp_detail_str(cpp, det, sizeof det);
            printf(" %s", det);
        }
        printf("%s\n", (e->flags & 0x01) ? " [oneway]" : "");
        if (g_mc->verbose && !iface) {
            printf("[binder-api]   raw[0..%zu):", n < 48 ? n : 48);
            for (size_t i = 0; i < n && i < 48; i++) printf(" %02x", e->raw[i]);
            printf("\n");
        }
    }
    if (g_mc->sink) {
        g_mc->sink->jb.len = 0;
        mod_emit_binder_api(&g_mc->sink->jb, e, iface, method, cpp);
        anubee_sink_emit(g_mc->sink);
    }
    return 0;
}

// ---- end-of-run counts (snapshotted in teardown, before the map goes) ---------

struct ba_count { struct binder_api_key k; __u64 count; };
static struct ba_count *g_counts = NULL;
static int g_ncounts = 0;

static void ba_snapshot_counts(void)
{
    if (!g_skel) return;
    int fd = bpf_map__fd(g_skel->maps.binder_api_counts);
    struct binder_api_key k, next;
    struct binder_api_val v;
    int cap = 0;
    void *prev = NULL;
    while (bpf_map_get_next_key(fd, prev, &next) == 0) {
        k = next;
        prev = &k;
        if (bpf_map_lookup_elem(fd, &k, &v) != 0) continue;
        if (g_ncounts == cap) {
            int nc = cap ? cap * 2 : 256;
            struct ba_count *p = realloc(g_counts, (size_t)nc * sizeof *p);
            if (!p) break;
            g_counts = p;
            cap = nc;
        }
        g_counts[g_ncounts++] = (struct ba_count){ k, v.count };
    }
}

static int ba_cmp(const void *a, const void *b)
{
    const struct ba_count *x = a, *y = b;
    if (x->k.tgid != y->k.tgid) return x->k.tgid < y->k.tgid ? -1 : 1;
    return x->count < y->count ? 1 : x->count > y->count ? -1 : 0;
}

// ---- lifecycle ------------------------------------------------------------------

static void ba_teardown(void);

static struct ring_buffer *ba_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_mc = mc;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    g_names = binder_names_load_device(&g_njar);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (!mc->quiet)
        printf("[binder-api] %d AIDL method name(s) from %d framework jar(s) (%ld ms)\n",
               binder_names_count(g_names), g_njar,
               (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000));

    g_skel = binder_api_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod binder-api: failed to open BPF skeleton\n");
        goto err;
    }
    if (binder_api_bpf__load(g_skel)) {
        fprintf(stderr, "mod binder-api: failed to load BPF\n");
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
    // Interfaces whose every call is reported (not just the first per method).
    static const char *const always[] = { "android.content.IContentProvider" };
    for (size_t i = 0; i < sizeof always / sizeof always[0]; i++) {
        __u64 h = binder_descriptor_hash(always[i]);
        bpf_map_update_elem(bpf_map__fd(g_skel->maps.binder_api_always), &h, &one, BPF_ANY);
    }
    g_link = bpf_program__attach(g_skel->progs.on_binder_transaction);
    if (!g_link) {
        fprintf(stderr, "mod binder-api: kprobe/binder_transaction unavailable (%s), aborting\n",
                strerror(errno));
        goto err;
    }
    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        g_ff = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (!g_ff) fprintf(stderr, "mod binder-api: follow-fork attach failed (non-fatal)\n");
    }
    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb), ba_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod binder-api: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;
err:
    ba_teardown();
    return NULL;
}

static void ba_teardown(void)
{
    if (g_link) { bpf_link__destroy(g_link); g_link = NULL; }
    if (g_ff)   { bpf_link__destroy(g_ff);   g_ff   = NULL; }
    if (g_rb)   { ring_buffer__free(g_rb);   g_rb   = NULL; }
    ba_snapshot_counts();
    if (g_skel) { binder_api_bpf__destroy(g_skel); g_skel = NULL; }
    if (g_counts) qsort(g_counts, (size_t)g_ncounts, sizeof *g_counts, ba_cmp);
}

#define BA_SUMMARY_TOP 15

static void ba_name(const struct binder_api_key *k, const char **iface, const char **method)
{
    *iface = ba_tok_get(k->token_hash);
    *method = *iface ? binder_names_lookup(g_names, *iface, k->code) : NULL;
}

static void ba_print_summary(void)
{
    if (g_ncp) {
        printf("[binder-api] --- content-provider access (%d distinct)%s\n", g_ncp,
               g_cp_overflow ? " -- table full, later ones not listed" : "");
        for (int i = 0; i < g_ncp; i++)
            printf("[binder-api]  %6u %8lu  %-10s %s\n", g_cp[i].pid, g_cp[i].count,
                   g_cp[i].method, g_cp[i].detail[0] ? g_cp[i].detail : "<no uri>");
    }
    if (g_ncounts == 0) return;
    printf("[binder-api] --- %lu distinct (process, interface, method); "
           "%lu unnamed code(s), %lu without a token\n", g_first_seen, g_unnamed, g_no_token);
    int shown = 0;
    for (int i = 0; i < g_ncounts; i++) {
        if (i && g_counts[i].k.tgid != g_counts[i - 1].k.tgid) shown = 0;
        if (shown++ >= BA_SUMMARY_TOP) continue;
        const char *iface, *method;
        ba_name(&g_counts[i].k, &iface, &method);
        printf("[binder-api]  %6u %8llu  %s.%s", g_counts[i].k.tgid,
               (unsigned long long)g_counts[i].count, iface ? iface : "<no-token>",
               method ? method : "");
        if (!method) printf("#%u", g_counts[i].k.code);
        printf("\n");
    }
}

static void ba_emit_summary(struct anubee_sink *s)
{
    if (g_ncounts == 0) return;
    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_s(j, "{\"type\":\"binder_api_summary\",\"processes\":[");
    for (int i = 0; i < g_ncounts; i++) {
        int first_of_pid = i == 0 || g_counts[i].k.tgid != g_counts[i - 1].k.tgid;
        if (first_of_pid) {
            if (i) jb_s(j, "]},");
            jb_s(j, "{\"pid\":"); jb_u64(j, g_counts[i].k.tgid); jb_s(j, ",\"calls\":[");
        } else {
            jb_c(j, ',');
        }
        const char *iface, *method;
        ba_name(&g_counts[i].k, &iface, &method);
        jb_s(j, "{\"interface\":");
        if (iface) { jb_c(j, '"'); jb_esc(j, iface); jb_c(j, '"'); } else jb_s(j, "null");
        jb_s(j, ",\"method\":");
        if (method) { jb_c(j, '"'); jb_esc(j, method); jb_c(j, '"'); } else jb_s(j, "null");
        jb_s(j, ",\"code\":");  jb_u64(j, g_counts[i].k.code);
        jb_s(j, ",\"count\":"); jb_u64(j, g_counts[i].count);
        jb_c(j, '}');
    }
    jb_s(j, "]}]");
    jb_s(j, ",\"content_access\":[");
    for (int i = 0; i < g_ncp; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");     jb_u64(j, g_cp[i].pid);
        jb_s(j, ",\"method\":\""); jb_esc(j, g_cp[i].method);
        jb_s(j, "\",\"detail\":\""); jb_esc(j, g_cp[i].detail);
        jb_s(j, "\",\"count\":");  jb_u64(j, g_cp[i].count);
        jb_c(j, '}');
    }
    jb_s(j, "]}");
    anubee_sink_emit(s);
}

static unsigned long long ba_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

const anubee_analyzer_t analyzer_binder_api = {
    .name          = "binder-api",
    .description   = "Which Binder interfaces/methods the app calls (first call of each "
                     "logged live, counts at exit; method names from the device's own "
                     "framework AIDL stubs) (stealthy -- kprobe, zero uprobes)",
    .setup         = ba_setup,
    .teardown      = ba_teardown,
    .print_summary = ba_print_summary,
    .emit_summary  = ba_emit_summary,
    .drops         = ba_drops,
};
