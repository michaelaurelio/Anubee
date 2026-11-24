// SPDX-License-Identifier: GPL-2.0
// BPF object for the binder-api analyzer: which Binder interfaces and methods
// the traced app calls. kprobe on the kernel's binder_transaction(), which
// runs in the sender's context with `tr` (the kernel copy of the caller's
// binder_transaction_data) -- so tr->data.ptr.buffer is a pointer into the
// sender's own Parcel, readable with bpf_probe_read_user. Read-only: nothing
// is written to the target (stealthy).
//
// An AIDL call's Parcel starts with the interface token (written by
// Parcel::writeInterfaceToken): int32 strict-mode policy, int32 work-source
// uid, int32 header magic ('SYST'/'VNDR'), then String16 = int32 length +
// UTF-16 chars. The token + transaction code identify the method. The
// kernel hashes the token to dedup: only the first (tgid, token, code) is
// sent up with the raw Parcel prefix; repeats just bump binder_api_counts --
// except tokens in binder_api_always, whose every call is sent.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 1024 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct binder_api_key);
	__type(value, struct binder_api_val);
} binder_api_counts SEC(".maps");

// Token hashes (FNV-1a, as below) whose every call is reported, not just the
// first: filled by userspace (IContentProvider -- each call carries its own URI).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} binder_api_always SEC(".maps");

#define TOKEN_OFF      12      // int32 length of the String16 token
#define TOKEN_MAX_CH   120     // longest token hashed (real ones are < 80)

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
	__u32 n = dsz < BINDER_API_RAW ? (__u32)dsz : BINDER_API_RAW;
	if (!buf || n < TOKEN_OFF + 4)
		return 0;

	// Reserve first and read the Parcel prefix straight into the event; it
	// is discarded below if this (process, interface, method) was seen.
	struct binder_api_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}
	if (n > BINDER_API_RAW)
		n = BINDER_API_RAW;   // explicit clamp for the verifier
	if (bpf_probe_read_user(e->raw, n, (void *)buf) != 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	// FNV-1a over the token's UTF-16 bytes (bounded by its own length,
	// the bytes actually read, and TOKEN_MAX_CH).
	__s32 len = 0;
	__builtin_memcpy(&len, &e->raw[TOKEN_OFF], 4);
	__u64 h = 0;
	if (len > 0 && len <= TOKEN_MAX_CH && TOKEN_OFF + 4 + 2 * len <= n) {
		h = 1469598103934665603ULL;
		for (int i = 0; i < 2 * TOKEN_MAX_CH; i++) {
			if (i >= 2 * len)
				break;
			h ^= e->raw[(TOKEN_OFF + 4 + i) & (BINDER_API_RAW - 1)];
			h *= 1099511628211ULL;
		}
	}

	__u64 id = bpf_get_current_pid_tgid();
	struct binder_api_key k = {
		.tgid = (__u32)(id >> 32),
		.code = BPF_CORE_READ(tr, code),
		.token_hash = h,
	};
	__u64 now = bpf_ktime_get_ns();
	struct binder_api_val *v = bpf_map_lookup_elem(&binder_api_counts, &k);
	if (v) {
		__sync_fetch_and_add(&v->count, 1);
		if (!h || !bpf_map_lookup_elem(&binder_api_always, &h)) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
	} else {
		struct binder_api_val nv = { .count = 1, .first_ts_ns = now };
		bpf_map_update_elem(&binder_api_counts, &k, &nv, BPF_NOEXIST);
	}

	e->h.type     = MOD_EV_BINDER_API;
	e->h.pid      = k.tgid;
	e->h.tid      = (__u32)id;
	e->h._pad     = 0;
	e->ts_ns      = now;
	e->token_hash = h;
	e->code       = k.code;
	e->flags      = BPF_CORE_READ(tr, flags);
	e->data_size  = (__u32)dsz;
	e->raw_len    = n;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
