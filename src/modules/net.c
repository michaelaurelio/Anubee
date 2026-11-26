// SPDX-License-Identifier: GPL-2.0
// `anubee mod net` — who the traced app talks to over the network, and how
// much: every outbound IPv4/IPv6 flow with its destination, the host name it
// carried (TLS SNI, HTTP Host, DNS question), bytes sent/received, and every
// name the app looks up through netd. Kernel side: src/modules/net.bpf.c;
// payload parsers: src/modules/net_parse.c.
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "net.skel.h"
#include "common/analyzer.h"
#include "common/engine_args.h"
#include "common/emit.h"
#include "common/runtime.h"
#include "modules/mod_events.h"
#include "modules/mod_emit.h"
#include "modules/net_parse.h"

#define NET_OPEN_MAX 1024   // flows open right now (userspace view)
#define NET_DEST_MAX 512    // distinct (proto, dest, host) in the summary
#define NET_DNS_MAX  512    // distinct names looked up

typedef struct {
    __u64 sk;
    char  host[256];
    char  host_source[8];
} net_open_t;

typedef struct {
    __u8  proto;
    char  dest[64];
    char  host[256];
    __u32 pid;
    char  comm[TASK_COMM_LEN];
    unsigned long long connections, tx, rx;
} net_dest_t;

typedef struct {
    char  host[256];
    __u32 pid;
    char  comm[TASK_COMM_LEN];
    unsigned long long count;
} net_dns_t;

static net_open_t net_open[NET_OPEN_MAX];
static int        net_open_count = 0;
static net_dest_t net_dests[NET_DEST_MAX];
static int        net_dest_count = 0;
static net_dns_t  net_dns[NET_DNS_MAX];
static int        net_dns_count = 0;
static unsigned   net_untracked = 0;   // summary tables full
static unsigned long long net_flows_lost = 0;   // kernel flow table full

static struct net_bpf    *g_skel = NULL;
static struct ring_buffer *g_rb = NULL;
static struct bpf_link    *g_links[10];
static int                 g_nlinks = 0;

static const char *proto_name(__u8 p) { return p == NET_PROTO_TCP ? "tcp" : "udp"; }

static net_dest_t *dest_get(__u8 proto, const char *dest, const char *host,
                            __u32 pid, const char *comm, int *created)
{
    *created = 0;
    for (int i = 0; i < net_dest_count; i++)
        if (net_dests[i].proto == proto && !strcmp(net_dests[i].dest, dest) &&
            !strcmp(net_dests[i].host, host))
            return &net_dests[i];
    if (net_dest_count >= NET_DEST_MAX) { net_untracked++; return NULL; }
    net_dest_t *d = &net_dests[net_dest_count++];
    memset(d, 0, sizeof *d);
    d->proto = proto;
    snprintf(d->dest, sizeof d->dest, "%s", dest);
    snprintf(d->host, sizeof d->host, "%s", host);
    d->pid = pid;
    snprintf(d->comm, sizeof d->comm, "%s", comm);
    *created = 1;
    return d;
}

// 1 if this is the first lookup of the name.
static int dns_note(const char *host, __u32 pid, const char *comm)
{
    for (int i = 0; i < net_dns_count; i++)
        if (!strcmp(net_dns[i].host, host)) { net_dns[i].count++; return 0; }
    if (net_dns_count >= NET_DNS_MAX) { net_untracked++; return 0; }
    net_dns_t *d = &net_dns[net_dns_count++];
    snprintf(d->host, sizeof d->host, "%s", host);
    d->pid = pid;
    snprintf(d->comm, sizeof d->comm, "%s", comm);
    d->count = 1;
    return 1;
}

static void fmt_dest(const struct net_event *e, char *out, size_t cap)
{
    net_fmt_dest(e->family, e->daddr, e->dport, out, cap);
}

// Host name carried by a flow's first bytes.
static const char *host_of(const struct net_event *e, char *host, size_t cap)
{
    size_t n = e->payload_len;
    if (net_tls_sni(e->payload, n, host, cap))  return "sni";
    if (net_http_host(e->payload, n, host, cap)) return "http";
    if (e->proto == NET_PROTO_UDP && e->dport == 53 && net_dns_qname(e->payload, n, host, cap))
        return "dns";
    host[0] = '\0';
    return NULL;
}

static int net_handle_event(void *ctx, void *data, size_t sz)
{
    struct anubee_mod_ctx *mc = ctx;
    const struct trace_event_header *hdr = data;
    if (hdr->type != MOD_EV_NET || sz < offsetof(struct net_event, payload))
        return 0;
    const struct net_event *e = data;
    if (e->kind != NET_EV_CLOSE && sz < sizeof *e)
        return 0;

    char dest[64] = "", host[256] = "";
    const char *src = NULL;

    if (e->kind == NET_EV_DNS) {
        if (!net_dnsproxy_host(e->payload, e->payload_len, host, sizeof host))
            return 0;
        if (dns_note(host, e->h.pid, e->comm) && !mc->quiet)
            printf("[net] PID:%-6d (%s) dns  %s\n", e->h.pid, e->comm, host);
        if (mc->sink) {
            mod_emit_net(&mc->sink->jb, e, NULL, host, "netd");
            anubee_sink_emit(mc->sink);
        }
        return 0;
    }

    fmt_dest(e, dest, sizeof dest);

    if (e->kind == NET_EV_OPEN) {
        src = host_of(e, host, sizeof host);
        if (src && !strcmp(src, "dns"))
            dns_note(host, e->h.pid, e->comm);
        if (net_open_count < NET_OPEN_MAX) {
            net_open_t *o = &net_open[net_open_count++];
            o->sk = e->sk;
            snprintf(o->host, sizeof o->host, "%s", host);
            snprintf(o->host_source, sizeof o->host_source, "%s", src ? src : "");
        }
        int created = 0;
        net_dest_t *d = dest_get(e->proto, dest, host, e->h.pid, e->comm, &created);
        if (d) d->connections++;
        if (created && !mc->quiet)
            printf("[net] PID:%-6d (%s) %s  %-40s %s%s%s%s\n", e->h.pid, e->comm,
                   proto_name(e->proto), dest, host[0] ? host : "",
                   src ? " (" : "", src ? src : "", src ? ")" : "");
        if (mc->sink) {
            mod_emit_net(&mc->sink->jb, e, dest, host[0] ? host : NULL, src);
            anubee_sink_emit(mc->sink);
        }
        return 0;
    }

    // CLOSE: the host comes from this flow's OPEN.
    for (int i = 0; i < net_open_count; i++) {
        if (net_open[i].sk != e->sk) continue;
        snprintf(host, sizeof host, "%s", net_open[i].host);
        static char srcbuf[8];
        snprintf(srcbuf, sizeof srcbuf, "%s", net_open[i].host_source);
        src = srcbuf[0] ? srcbuf : NULL;
        net_open[i] = net_open[--net_open_count];
        break;
    }
    int created = 0;
    net_dest_t *d = dest_get(e->proto, dest, host, e->h.pid, e->comm, &created);
    if (d) {
        if (created) d->connections++;   // its OPEN never reached us
        d->tx += e->tx;
        d->rx += e->rx;
    }
    if (mc->sink) {
        mod_emit_net(&mc->sink->jb, e, dest, host[0] ? host : NULL, src);
        anubee_sink_emit(mc->sink);
    }
    return 0;
}

// ---- BPF lifecycle ----------------------------------------------------------------

static void net_teardown(void);

static struct ring_buffer *net_setup(int uid, struct anubee_mod_ctx *mc)
{
    g_skel = net_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "mod net: failed to open BPF skeleton\n");
        return NULL;
    }
    if (net_bpf__load(g_skel)) {
        fprintf(stderr, "mod net: failed to load BPF\n");
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
        g_skel->progs.on_tcp_sendmsg, g_skel->progs.on_udp_sendmsg,
        g_skel->progs.on_udpv6_sendmsg, g_skel->progs.on_tcp_cleanup_rbuf,
        g_skel->progs.on_skb_consume_udp, g_skel->progs.on_inet_release,
        g_skel->progs.on_unix_stream_sendmsg,
    };
    for (unsigned i = 0; i < sizeof progs / sizeof progs[0]; i++) {
        struct bpf_link *l = bpf_program__attach(progs[i]);
        if (!l && progs[i] == g_skel->progs.on_tcp_cleanup_rbuf)   // pre-6.x kernels
            l = bpf_program__attach_kprobe(progs[i], false, "tcp_cleanup_rbuf");
        if (!l) {
            fprintf(stderr, "mod net: attaching %s failed (%s), aborting\n",
                    bpf_program__name(progs[i]), strerror(errno));
            goto err;
        }
        g_links[g_nlinks++] = l;
    }
    if (mc->tgt && mc->tgt->n > 0 && !mc->tgt->no_follow) {
        struct bpf_link *l = bpf_program__attach(g_skel->progs.anubee_follow_fork);
        if (l) g_links[g_nlinks++] = l;
        else fprintf(stderr, "mod net: follow-fork attach failed (non-fatal)\n");
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb), net_handle_event, mc, NULL);
    if (!g_rb) {
        fprintf(stderr, "mod net: failed to create ring buffer\n");
        goto err;
    }
    return g_rb;

err:
    net_teardown();
    return NULL;
}

// Flows still open when tracing stops: fold their totals into the summary.
static void net_fold_open_flows(void)
{
    int fd = bpf_map__fd(g_skel->maps.flows);
    __u64 key, next, *prev = NULL;
    struct net_flow f;
    while (bpf_map_get_next_key(fd, prev, &next) == 0) {
        key = next;
        prev = &key;
        if (bpf_map_lookup_elem(fd, &key, &f)) continue;
        struct net_event e = { 0 };
        e.family = f.family;
        e.dport = f.dport;
        memcpy(e.daddr, f.daddr, 16);
        char dest[64], host[256] = "";
        fmt_dest(&e, dest, sizeof dest);
        int was_seen = 0;
        for (int i = 0; i < net_open_count; i++)
            if (net_open[i].sk == key) {
                snprintf(host, sizeof host, "%s", net_open[i].host);
                was_seen = 1;
                break;
            }
        int created = 0;
        net_dest_t *d = dest_get(f.proto, dest, host, f.pid, f.comm, &created);
        if (!d) continue;
        if (created || !was_seen) d->connections++;   // its OPEN never reached us
        d->tx += f.tx;
        d->rx += f.rx;
    }
}

static void net_teardown(void)
{
    while (g_nlinks > 0) bpf_link__destroy(g_links[--g_nlinks]);
    if (g_rb)   { ring_buffer__consume(g_rb); ring_buffer__free(g_rb); g_rb = NULL; }
    if (g_skel) {
        net_fold_open_flows();
        __u32 z = 0;
        bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.flows_lost), &z, &net_flows_lost);
        net_bpf__destroy(g_skel);
        g_skel = NULL;
    }
}

// ---- summary ---------------------------------------------------------------------

static int by_bytes(const void *a, const void *b)
{
    const net_dest_t *x = a, *y = b;
    unsigned long long tx = x->tx + x->rx, ty = y->tx + y->rx;
    return tx < ty ? 1 : tx > ty ? -1 : 0;
}

static void net_print_summary(void)
{
    if (net_dest_count == 0 && net_dns_count == 0) return;
    qsort(net_dests, (size_t)net_dest_count, sizeof net_dests[0], by_bytes);
    printf("[net] --- Destinations (by bytes) ---\n");
    printf("[net]  %-4s %-40s %-32s %5s %12s %12s\n", "", "dest", "host", "conns", "sent", "received");
    for (int i = 0; i < net_dest_count; i++) {
        const net_dest_t *d = &net_dests[i];
        printf("[net]  %-4s %-40s %-32s %5llu %12llu %12llu\n", proto_name(d->proto), d->dest,
               d->host[0] ? d->host : "-", d->connections, d->tx, d->rx);
    }
    if (net_dns_count) {
        printf("[net] --- Names looked up ---\n");
        for (int i = 0; i < net_dns_count; i++)
            printf("[net]  %5llux %s\n", net_dns[i].count, net_dns[i].host);
    }
    if (net_untracked)
        printf("[net]  %u more destinations/names not tracked (table full)\n", net_untracked);
    if (net_flows_lost)
        printf("[net]  %llu flows not traced (kernel flow table full)\n", net_flows_lost);
}

static void net_emit_summary(struct anubee_sink *s)
{
    if (net_dest_count == 0 && net_dns_count == 0) return;
    struct jbuf *j = &s->jb;
    j->len = 0;
    jb_s(j, "{\"type\":\"net_summary\",\"destination_count\":");
    jb_u64(j, (unsigned long long)net_dest_count);
    jb_s(j, ",\"untracked\":"); jb_u64(j, net_untracked + net_flows_lost);
    jb_s(j, ",\"destinations\":[");
    for (int i = 0; i < net_dest_count; i++) {
        const net_dest_t *d = &net_dests[i];
        if (i) jb_c(j, ',');
        jb_s(j, "{\"proto\":\"");   jb_s(j, proto_name(d->proto));
        jb_s(j, "\",\"dest\":\"");  jb_esc(j, d->dest);
        jb_s(j, "\",\"host\":");
        if (d->host[0]) { jb_c(j, '"'); jb_esc(j, d->host); jb_c(j, '"'); } else jb_s(j, "null");
        jb_s(j, ",\"pid\":");       jb_u64(j, d->pid);
        jb_s(j, ",\"comm\":\"");    jb_esc(j, d->comm);
        jb_s(j, "\",\"connections\":"); jb_u64(j, d->connections);
        jb_s(j, ",\"tx\":");        jb_u64(j, d->tx);
        jb_s(j, ",\"rx\":");        jb_u64(j, d->rx);
        jb_c(j, '}');
    }
    jb_s(j, "],\"lookups\":[");
    for (int i = 0; i < net_dns_count; i++) {
        if (i) jb_c(j, ',');
        jb_s(j, "{\"host\":\"");   jb_esc(j, net_dns[i].host);
        jb_s(j, "\",\"count\":");  jb_u64(j, net_dns[i].count);
        jb_s(j, ",\"pid\":");      jb_u64(j, net_dns[i].pid);
        jb_s(j, ",\"comm\":\"");   jb_esc(j, net_dns[i].comm);
        jb_s(j, "\"}");
    }
    jb_s(j, "]}");
    anubee_sink_emit(s);
}

static unsigned long long net_drops(void)
{
    return g_skel ? anubee_drops_read(bpf_map__fd(g_skel->maps.dropped)) : 0;
}

const anubee_analyzer_t analyzer_net = {
    .name          = "net",
    .description   = "Network: every outbound IPv4/IPv6 flow with its destination, the host "
                      "it named (TLS SNI, HTTP Host, DNS), bytes sent/received, and every "
                      "name looked up through netd (kprobes only, zero uprobes)",
    .setup         = net_setup,
    .teardown      = net_teardown,
    .print_summary = net_print_summary,
    .emit_summary  = net_emit_summary,
    .drops         = net_drops,
};
