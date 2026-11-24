// SPDX-License-Identifier: GPL-2.0
// BPF object for the net analyzer: who the traced app talks to, and how much.
// One flow per outbound IPv4/IPv6 socket (keyed by its struct sock):
//   - kprobe/tcp_sendmsg, udp_sendmsg, udpv6_sendmsg -- the first send of a
//     flow from a traced process creates it and emits OPEN with the first
//     bytes sent (TLS ClientHello -> SNI, HTTP request -> Host, DNS query ->
//     name; userspace parses them, net_parse.c); every send adds to tx.
//   - kprobe/__tcp_cleanup_rbuf (TCP bytes the app read; tcp_recvmsg calls
//     it directly since 6.x -- the plain tcp_cleanup_rbuf on older kernels) and skb_consume_udp
//     (UDP datagrams it received) add to rx.
//   - kprobe/inet_release (close() of an IPv4 or IPv6 socket) emits CLOSE
//     with the totals and forgets the flow.
//   - kprobe/unix_stream_sendmsg: a getaddrinfo/gethostbyname/resnsend
//     command written to netd's dnsproxyd socket -- how every app's libc
//     resolves names -- emits DNS with the command text.
// Loopback/unspecified destinations are local IPC, not network, and skipped
// (exfil_detect_addr.h). Kernel-side only: no uprobes, nothing written into
// the target.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"
#include "modules/exfil_detect_addr.h"

#define NET_FLOW_MAX 8192

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NET_FLOW_MAX);
	__type(key, __u64);
	__type(value, struct net_flow);
} flows SEC(".maps");

// Flows the table had no room for (counted in drops too).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} flows_lost SEC(".maps");

static __always_inline int traced(void)
{
	return uid_matches() || pid_matches();
}

static __always_inline void ev_head(struct net_event *e, __u8 kind)
{
	__u64 id = bpf_get_current_pid_tgid();
	e->h.type = MOD_EV_NET;
	e->h.pid  = (__u32)(id >> 32);
	e->h.tid  = (__u32)id;
	e->h._pad = 0;
	e->ts_ns  = bpf_ktime_get_ns();
	e->kind   = kind;
	e->_pad   = 0;
	e->first_ts_ns = 0;
	e->tx = 0;
	e->rx = 0;
	e->payload_len = 0;
}

// Heap pointers carry an Android tag in the top byte (TBI/MTE); the kernel's
// user-copy helpers want it stripped.
#define NET_UNTAG(p) ((unsigned long)(p) & 0x00FFFFFFFFFFFFFFul)

// First user buffer behind a msghdr's iterator: write()/send() give a single
// ITER_UBUF, sendmsg()/writev() an ITER_IOVEC array (copied into the kernel).
static __always_inline int msg_buf(struct msghdr *msg, unsigned long *ptr, __u64 *len)
{
	__u8 t = BPF_CORE_READ(msg, msg_iter.iter_type);
	__u64 off = BPF_CORE_READ(msg, msg_iter.iov_offset);
	if (t == ITER_UBUF) {
		*ptr = NET_UNTAG(BPF_CORE_READ(msg, msg_iter.ubuf)) + off;
		*len = BPF_CORE_READ(msg, msg_iter.count);
		return 1;
	}
	if (t == ITER_IOVEC) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		struct iovec v;
		if (!iov || bpf_probe_read_kernel(&v, sizeof(v), iov))
			return 0;
		if (v.iov_len <= off)
			return 0;
		*ptr = NET_UNTAG(v.iov_base) + off;
		*len = v.iov_len - off;
		return 1;
	}
	return 0;   // kernel/bvec iterators (sendfile, splice): no user bytes to show
}

static __always_inline void read_payload(struct net_event *e, struct msghdr *msg, __u64 size)
{
	unsigned long ptr;
	__u64 len;
	if (!msg_buf(msg, &ptr, &len))
		return;
	if (len > size)
		len = size;
	__u32 n = len > NET_PAYLOAD_LEN ? NET_PAYLOAD_LEN : (__u32)len;
	if (n == 0 || n > NET_PAYLOAD_LEN)
		return;
	if (bpf_probe_read_user(e->payload, n, (void *)ptr) == 0)
		e->payload_len = (__u16)n;
}

static __always_inline void emit_close(__u64 key, struct net_flow *f)
{
	struct net_event *e = bpf_ringbuf_reserve(&events_rb,
		sizeof(struct net_event) - NET_PAYLOAD_LEN, 0);
	if (!e) {
		bump_dropped();
		return;
	}
	ev_head(e, NET_EV_CLOSE);
	e->h.pid = f->pid;   // the flow's owner, not whoever released it
	e->sk = key;
	e->first_ts_ns = f->first_ts_ns;
	e->tx = f->tx;
	e->rx = f->rx;
	e->proto = f->proto;
	e->family = f->family;
	e->dport = f->dport;
	__builtin_memcpy(e->daddr, f->daddr, 16);
	__builtin_memcpy(e->comm, f->comm, TASK_COMM_LEN);
	bpf_ringbuf_submit(e, 0);
}

// Peer of a connected socket: family, address (16 bytes, network order),
// port (host order). 0 if not IPv4/IPv6.
static __always_inline int sk_peer(struct sock *sk, __u8 *fam, __u8 *addr, __u16 *dport)
{
	__u16 f = BPF_CORE_READ(sk, __sk_common.skc_family);
	__builtin_memset(addr, 0, 16);
	*dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (f == EXFIL_AF_INET) {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(addr, &a, 4);
	} else if (f == EXFIL_AF_INET6) {
		BPF_CORE_READ_INTO((struct in6_addr *)addr, sk, __sk_common.skc_v6_daddr);
	} else {
		return 0;
	}
	*fam = (__u8)f;
	return 1;
}

// A send of `size` bytes on sk to (fam, addr, dport).
static __always_inline void flow_send(struct sock *sk, struct msghdr *msg, __u64 size,
				      __u8 proto, __u8 fam, const __u8 *addr, __u16 dport)
{
	__u64 key = (__u64)sk;
	struct net_flow *f = bpf_map_lookup_elem(&flows, &key);

	// An unconnected UDP socket can send to many peers: each new peer ends
	// the previous flow and starts another on the same socket.
	if (f && proto == NET_PROTO_UDP &&
	    (f->dport != dport ||
	     *(__u64 *)f->daddr != *(const __u64 *)addr ||
	     *(__u64 *)(f->daddr + 8) != *(const __u64 *)(addr + 8))) {
		emit_close(key, f);
		bpf_map_delete_elem(&flows, &key);
		f = NULL;
	}
	if (f) {
		__sync_fetch_and_add(&f->tx, size);
		return;
	}

	if (!traced() || !exfil_addr_is_outbound(fam, addr))
		return;

	struct net_flow nf = {};
	nf.first_ts_ns = bpf_ktime_get_ns();
	nf.tx = size;
	nf.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	nf.proto = proto;
	nf.family = fam;
	nf.dport = dport;
	__builtin_memcpy(nf.daddr, addr, 16);
	bpf_get_current_comm(nf.comm, sizeof(nf.comm));
	if (bpf_map_update_elem(&flows, &key, &nf, BPF_NOEXIST)) {
		__u32 z = 0;
		__u64 *lost = bpf_map_lookup_elem(&flows_lost, &z);
		if (lost)
			__sync_fetch_and_add(lost, 1);
		bump_dropped();
		return;
	}

	struct net_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return;
	}
	ev_head(e, NET_EV_OPEN);
	e->sk = key;
	e->first_ts_ns = nf.first_ts_ns;
	e->proto = proto;
	e->family = fam;
	e->dport = dport;
	__builtin_memcpy(e->daddr, addr, 16);
	__builtin_memcpy(e->comm, nf.comm, TASK_COMM_LEN);
	read_payload(e, msg, size);
	bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(on_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	__u8 fam, addr[16];
	__u16 dport;
	if (!sk_peer(sk, &fam, addr, &dport))
		return 0;
	flow_send(sk, msg, size, NET_PROTO_TCP, fam, addr, dport);
	return 0;
}

// UDP destination: the sendto()/sendmsg() address if one was given (the
// kernel's copy in msg_name), else the connected peer.
static __always_inline void udp_send(struct sock *sk, struct msghdr *msg, __u64 len)
{
	__u8 fam, addr[16];
	__u16 dport;
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		unsigned char sa[24];
		if (bpf_probe_read_kernel(sa, sizeof(sa), name))
			return;
		__u16 f = (__u16)(sa[0] | (sa[1] << 8));
		__builtin_memset(addr, 0, 16);
		dport = (__u16)(sa[2] << 8 | sa[3]);
		if (f == EXFIL_AF_INET)
			__builtin_memcpy(addr, sa + 4, 4);
		else if (f == EXFIL_AF_INET6)
			__builtin_memcpy(addr, sa + 8, 16);
		else
			return;
		fam = (__u8)f;
	} else if (!sk_peer(sk, &fam, addr, &dport)) {
		return;
	}
	flow_send(sk, msg, len, NET_PROTO_UDP, fam, addr, dport);
}

// udpv6_sendmsg hands v4-mapped destinations to udp_sendmsg: count an
// AF_INET6 socket only in the v6 hook so nothing is counted twice.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(on_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	if (BPF_CORE_READ(sk, __sk_common.skc_family) != EXFIL_AF_INET)
		return 0;
	udp_send(sk, msg, len);
	return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(on_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	udp_send(sk, msg, len);
	return 0;
}

SEC("kprobe/__tcp_cleanup_rbuf")
int BPF_KPROBE(on_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;
	__u64 key = (__u64)sk;
	struct net_flow *f = bpf_map_lookup_elem(&flows, &key);
	if (f)
		__sync_fetch_and_add(&f->rx, (__u64)copied);
	return 0;
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(on_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
	if (len <= 0)
		return 0;
	__u64 key = (__u64)sk;
	struct net_flow *f = bpf_map_lookup_elem(&flows, &key);
	if (f)
		__sync_fetch_and_add(&f->rx, (__u64)len);
	return 0;
}

SEC("kprobe/inet_release")
int BPF_KPROBE(on_inet_release, struct socket *sock)
{
	__u64 key = (__u64)BPF_CORE_READ(sock, sk);
	struct net_flow *f = bpf_map_lookup_elem(&flows, &key);
	if (!f)
		return 0;
	emit_close(key, f);
	bpf_map_delete_elem(&flows, &key);
	return 0;
}

// The commands bionic sends to /dev/socket/dnsproxyd (netd).
static __always_inline int is_dns_cmd(const char *b)
{
	if (b[0] == 'g' && b[1] == 'e' && b[2] == 't')
		return (b[3] == 'a' && b[4] == 'd' && b[5] == 'd' && b[6] == 'r' && b[11] == ' ') ||
		       (b[3] == 'h' && b[4] == 'o' && b[5] == 's' && b[6] == 't' && b[13] == ' ');
	return b[0] == 'r' && b[1] == 'e' && b[2] == 's' && b[3] == 'n' && b[4] == 's' &&
	       b[5] == 'e' && b[6] == 'n' && b[7] == 'd' && b[8] == ' ';
}

SEC("kprobe/unix_stream_sendmsg")
int BPF_KPROBE(on_unix_stream_sendmsg, struct socket *sock, struct msghdr *msg, size_t len)
{
	if (!traced() || len < 16)
		return 0;
	unsigned long ptr;
	__u64 blen;
	if (!msg_buf(msg, &ptr, &blen) || blen < 16)
		return 0;
	char head[16];
	if (bpf_probe_read_user(head, sizeof(head), (void *)ptr) || !is_dns_cmd(head))
		return 0;

	struct net_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}
	ev_head(e, NET_EV_DNS);
	e->sk = 0;
	e->proto = 0;
	e->family = 0;
	e->dport = 0;
	__builtin_memset(e->daddr, 0, 16);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	read_payload(e, msg, len);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
