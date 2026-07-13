// SPDX-License-Identifier: GPL-2.0
// `ares mod exfil-burst` — userspace analyzer for the sensitive-read-then-
// network-burst signal. Owns the exfil_burst BPF skeleton lifecycle; the
// dispatcher in mod.c drives the poll loop and teardown order. Kernel side:
// src/modules/exfil_burst.bpf.c. No classification module (unlike
// ransomware_burst) -- crossing the byte threshold IS the detection
// decision, already made in BPF.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "exfil_burst.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/decode.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"

// ── per-pid tally (tallied unconditionally so summary survives -o) ─────────

#define EB_STAT_MAX 64

typedef struct {
    __u32              pid;
    char               comm[TASK_COMM_LEN];
    uint32_t           burst_count;
    unsigned long long max_bytes_sent;
} eb_stat_t;

static eb_stat_t eb_stats[EB_STAT_MAX];
static int       eb_stat_count = 0;

static void eb_stat_add(__u32 pid, const char *comm, unsigned long long bytes_sent)
{
    for (int i = 0; i < eb_stat_count; i++) {
        if (eb_stats[i].pid == pid) {
            eb_stats[i].burst_count++;
            if (bytes_sent > eb_stats[i].max_bytes_sent)
                eb_stats[i].max_bytes_sent = bytes_sent;
            return;
        }
    }
    if (eb_stat_count >= EB_STAT_MAX) return;
    eb_stats[eb_stat_count].pid = pid;
    snprintf(eb_stats[eb_stat_count].comm, TASK_COMM_LEN, "%s", comm);
    eb_stats[eb_stat_count].burst_count = 1;
    eb_stats[eb_stat_count].max_bytes_sent = bytes_sent;
    eb_stat_count++;
}

static struct exfil_burst_bpf *g_skel        = NULL;
static struct bpf_link        *eb_ff         = NULL;
static struct ring_buffer     *g_rb          = NULL;
static struct bpf_link        *openat_link   = NULL;
static struct bpf_link        *openat2_link  = NULL;
static struct bpf_link        *connect_link  = NULL;
static struct bpf_link        *sendto_link   = NULL;
static struct bpf_link        *write_link    = NULL;
static struct bpf_link        *writev_link   = NULL;
static struct bpf_link        *close_link    = NULL;

// ---- ring-buffer callback ---------------------------------------------------

static int eb_handle_event(void *ctx, void *data, size_t sz)
{
    struct ares_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;

    if (hdr->type != MOD_EV_EXFIL_BURST || sz < sizeof(struct exfil_burst_event))
        return 0;

    const struct exfil_burst_event *e = data;
    char dest_buf[64];
    const char *dest_str = NULL;
    if (e->dest_len > 0 &&
        decode_sockaddr(e->dest, e->dest_len, dest_buf, sizeof(dest_buf)))
        dest_str = dest_buf;

    eb_stat_add(e->h.pid, e->comm, e->bytes_sent);

    if (!mc->quiet) {
        printf("[exfil] PID:%-6d (%s) %llu bytes, %ums window, read %s, dest %s\n",
               e->h.pid, e->comm, (unsigned long long)e->bytes_sent, e->window_ms,
               e->sample_path, dest_str ? dest_str : "unknown");
    }

    if (mc->sink != NULL) {
        mod_emit_exfil_burst(&mc->sink->jb, e, dest_str);
        ares_sink_emit(mc->sink);
    }

    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------

static struct ring_buffer *eb_setup(int uid, struct ares_mod_ctx *mc)
{
    g_skel = exfil_burst_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod exfil-burst: failed to open BPF skeleton\n");
        return NULL;
    }
    if (exfil_burst_bpf__load(g_skel)) {
        fprintf(stderr, "mod exfil-burst: failed to load BPF\n");
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
    connect_link = bpf_program__attach(g_skel->progs.on_connect);
    sendto_link  = bpf_program__attach(g_skel->progs.on_sendto);
    write_link   = bpf_program__attach(g_skel->progs.on_write);
    writev_link  = bpf_program__attach(g_skel->progs.on_writev);
    close_link   = bpf_program__attach(g_skel->progs.on_close);

    if (!openat_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_openat unavailable\n");
    if (!openat2_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_openat2 unavailable (non-fatal)\n");
    if (!connect_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_connect unavailable\n");
    if (!sendto_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_sendto unavailable (non-fatal)\n");
    if (!write_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_write unavailable\n");
    if (!writev_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_writev unavailable (non-fatal)\n");
    if (!close_link)
        fprintf(stderr, "mod exfil-burst: kprobe/__arm64_sys_close unavailable (fd tracking degraded, non-fatal)\n");

    if (!openat_link && !openat2_link) {
        fprintf(stderr, "mod exfil-burst: no openat kprobe attached, aborting\n");
        goto err;
    }
    if (!connect_link) {
        fprintf(stderr, "mod exfil-burst: no connect kprobe attached, aborting\n");
        goto err;
    }
    if (!write_link && !writev_link && !sendto_link) {
        fprintf(stderr, "mod exfil-burst: no send-path kprobe attached, aborting\n");
        goto err;
    }

    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        eb_ff = bpf_program__attach(g_skel->progs.ares_follow_fork);
        if (!eb_ff) fprintf(stderr, "mod exfil-burst: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb),
                            eb_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod exfil-burst: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    if (eb_ff)         { bpf_link__destroy(eb_ff);         eb_ff         = NULL; }
    if (openat_link)   { bpf_link__destroy(openat_link);   openat_link   = NULL; }
    if (openat2_link)  { bpf_link__destroy(openat2_link);  openat2_link  = NULL; }
    if (connect_link)  { bpf_link__destroy(connect_link);  connect_link  = NULL; }
    if (sendto_link)   { bpf_link__destroy(sendto_link);   sendto_link   = NULL; }
    if (write_link)    { bpf_link__destroy(write_link);    write_link    = NULL; }
    if (writev_link)   { bpf_link__destroy(writev_link);   writev_link   = NULL; }
    if (close_link)    { bpf_link__destroy(close_link);    close_link    = NULL; }
    if (g_skel)        { exfil_burst_bpf__destroy(g_skel); g_skel        = NULL; }
    return NULL;
}

static void eb_teardown(void)
{
    if (eb_ff)         { bpf_link__destroy(eb_ff);         eb_ff         = NULL; }
    if (openat_link)   { bpf_link__destroy(openat_link);   openat_link   = NULL; }
    if (openat2_link)  { bpf_link__destroy(openat2_link);  openat2_link  = NULL; }
    if (connect_link)  { bpf_link__destroy(connect_link);  connect_link  = NULL; }
    if (sendto_link)   { bpf_link__destroy(sendto_link);   sendto_link   = NULL; }
    if (write_link)    { bpf_link__destroy(write_link);    write_link    = NULL; }
    if (writev_link)   { bpf_link__destroy(writev_link);   writev_link   = NULL; }
    if (close_link)    { bpf_link__destroy(close_link);    close_link    = NULL; }
    if (g_rb)          { ring_buffer__free(g_rb);          g_rb          = NULL; }
    if (g_skel)        { exfil_burst_bpf__destroy(g_skel); g_skel        = NULL; }
}

// ---- summary ----------------------------------------------------------------

static void eb_print_summary(void)
{
    if (eb_stat_count == 0) return;

    printf("[exfil] --- Exfil Burst Summary -----------------------------\n");
    printf("[exfil]   PID     Comm             Bursts  MaxBytesSent\n");
    for (int i = 0; i < eb_stat_count; i++) {
        printf("[exfil]  %6u  %-16s  %6u  %12llu\n",
               eb_stats[i].pid, eb_stats[i].comm, eb_stats[i].burst_count,
               eb_stats[i].max_bytes_sent);
    }
    printf("[exfil]  %d process%s triggered an exfil burst\n",
           eb_stat_count, eb_stat_count == 1 ? "" : "es");
}

// File twin of eb_print_summary: same tally, one
// {"type":"exfil_burst_summary",...} record.
static void eb_emit_summary(struct ares_sink *s)
{
    if (eb_stat_count == 0) return;

    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"exfil_burst_summary\"");
    jb_s(j, ",\"process_count\":"); jb_u64(j, (unsigned long long)eb_stat_count);
    jb_s(j, ",\"processes\":[");
    for (int i = 0; i < eb_stat_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"pid\":");        jb_u64(j, eb_stats[i].pid);
        jb_s(j, ",\"comm\":\"");     jb_esc(j, eb_stats[i].comm); jb_c(j, '"');
        jb_s(j, ",\"bursts\":");     jb_u64(j, eb_stats[i].burst_count);
        jb_s(j, ",\"max_bytes_sent\":"); jb_u64(j, eb_stats[i].max_bytes_sent);
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
    ares_sink_emit(s);
}

static unsigned long long eb_drops(void)
{
    return g_skel ? ares_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

// ---- analyzer registration --------------------------------------------------

const ares_analyzer_t analyzer_exfil_burst = {
    .name          = "exfil-burst",
    .description   = "Detect a network byte-volume burst following a sensitive "
                      "media/credential file read (bulk exfiltration signal; "
                      "stealthy -- kprobes, zero uprobes)",
    .setup         = eb_setup,
    .teardown      = eb_teardown,
    .print_summary = eb_print_summary,
    .emit_summary  = eb_emit_summary,
    .drops         = eb_drops,
};
