// SPDX-License-Identifier: GPL-2.0
// BPF object for the screencapture-detect analyzer: the traced app's Binder
// calls on the screen-capture interfaces (IMediaProjection, IDisplayManager).
// kprobe on the kernel's binder_transaction() (sender's context, as
// binder_api.bpf.c): read the start of the sender's Parcel, hash the AIDL
// interface token, keep only tokens userspace armed in sc_tokens. The first
// (process, interface, code) is sent up; repeats are counted in sc_counts.
// Userspace names the method and decides the capture stage
// (screencapture_detect_parse.c); a dumpsys poll there supplies the
// foreground-service stage. Read-only: nothing is written to the target.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"
#include "modules/binder_token.bpf.h"

#define SC_SCRATCH 256   // power of two; the tokens watched are ~40 chars

// Token hashes (binder_descriptor_hash) of the watched interfaces.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u64);
	__type(value, __u8);
} sc_tokens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct binder_api_key);
	__type(value, __u64);
} sc_counts SEC(".maps");

struct sc_buf { unsigned char b[SC_SCRATCH]; };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sc_buf);
} sc_scratch SEC(".maps");

SEC("kprobe/binder_transaction")
int BPF_KPROBE(on_binder_transaction, void *proc, void *thread,
	       struct binder_transaction_data *tr, int reply)
{
	if (reply)
		return 0;
	if (!uid_matches() && !pid_matches())
		return 0;

	// Strip the arm64 top-byte tag (Scudo/MTE heap pointers): the uaccess
	// check behind bpf_probe_read_user rejects tagged addresses.
	__u64 buf = BPF_CORE_READ(tr, data.ptr.buffer) & 0x00FFFFFFFFFFFFFFULL;
	__u64 dsz = BPF_CORE_READ(tr, data_size);
	__u32 n = dsz < SC_SCRATCH ? (__u32)dsz : SC_SCRATCH;
	if (!buf || n < BINDER_TOKEN_LEN_OFF + 4)
		return 0;
	__u32 zk = 0;
	struct sc_buf *s = bpf_map_lookup_elem(&sc_scratch, &zk);
	if (!s)
		return 0;
	if (n > SC_SCRATCH)
		n = SC_SCRATCH;   // explicit clamp for the verifier
	if (bpf_probe_read_user(s->b, n, (void *)buf) != 0)
		return 0;
	__u64 h = binder_token_fnv(s->b, SC_SCRATCH - 1, n);
	if (!h || !bpf_map_lookup_elem(&sc_tokens, &h))
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	struct binder_api_key k = {
		.tgid = (__u32)(id >> 32),
		.code = BPF_CORE_READ(tr, code),
		.token_hash = h,
	};
	__u64 *cnt = bpf_map_lookup_elem(&sc_counts, &k);
	if (cnt) {
		__sync_fetch_and_add(cnt, 1);
		return 0;
	}
	__u64 one = 1;
	bpf_map_update_elem(&sc_counts, &k, &one, BPF_NOEXIST);

	struct screencapture_detect_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}
	e->h.type     = MOD_EV_SCREENCAPTURE_DETECT;
	e->h.pid      = k.tgid;
	e->h.tid      = (__u32)id;
	e->h._pad     = 0;
	e->ts_ns      = bpf_ktime_get_ns();
	e->token_hash = h;
	e->code       = k.code;
	e->_pad       = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
