// SPDX-License-Identifier: GPL-2.0
// BPF object for the accessibility-detect analyzer: calls the traced app makes
// on android.accessibilityservice.IAccessibilityServiceConnection -- the
// channel through which an app's own AccessibilityService reads other apps'
// screens, clicks, injects gestures and takes screenshots. Accessibility
// abuse (overlay/ATS fraud, screen reading, security-prompt bypass) is the
// dominant technique across current Android banking trojans; a call on this
// interface means the app's service is live and working, not merely granted.
//
// kprobe on the kernel's binder_transaction() (sender's context, as
// binder_api.bpf.c): read the start of the sender's Parcel, hash the AIDL
// interface token, keep only calls whose hash matches the one userspace armed
// in a11y_token. The first (process, transaction code) is sent up; repeats
// are counted in a11y_counts. Read-only: nothing is written to the target.
// Userspace classification: src/modules/accessibility_detect_classify.c.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

#include "common/uid_filter.bpf.h"
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#include "common/bpf_drop.bpf.h"
#include "modules/mod_events.h"
#include "modules/binder_token.bpf.h"

#define A11Y_SCRATCH 256   // power of two; the 61-char token needs 16 + 122 bytes

// Token hash of IAccessibilityServiceConnection, set by userspace before
// attach (binder_descriptor_hash). 0 = unarmed: nothing matches.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} a11y_token SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct a11y_key);
	__type(value, __u64);
} a11y_counts SEC(".maps");

struct a11y_buf { unsigned char b[A11Y_SCRATCH]; };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct a11y_buf);
} a11y_scratch SEC(".maps");

SEC("kprobe/binder_transaction")
int BPF_KPROBE(on_binder_transaction, void *proc, void *thread,
	       struct binder_transaction_data *tr, int reply)
{
	if (reply)
		return 0;
	if (!uid_matches() && !pid_matches())
		return 0;

	__u32 zk = 0;
	__u64 *want = bpf_map_lookup_elem(&a11y_token, &zk);
	if (!want || !*want)
		return 0;

	// Strip the arm64 top-byte tag (Scudo/MTE heap pointers): the uaccess
	// check behind bpf_probe_read_user rejects tagged addresses.
	__u64 buf = BPF_CORE_READ(tr, data.ptr.buffer) & 0x00FFFFFFFFFFFFFFULL;
	__u64 dsz = BPF_CORE_READ(tr, data_size);
	__u32 n = dsz < A11Y_SCRATCH ? (__u32)dsz : A11Y_SCRATCH;
	if (!buf || n < BINDER_TOKEN_LEN_OFF + 4)
		return 0;
	struct a11y_buf *s = bpf_map_lookup_elem(&a11y_scratch, &zk);
	if (!s)
		return 0;
	if (n > A11Y_SCRATCH)
		n = A11Y_SCRATCH;   // explicit clamp for the verifier
	if (bpf_probe_read_user(s->b, n, (void *)buf) != 0)
		return 0;
	if (binder_token_fnv(s->b, A11Y_SCRATCH - 1, n) != *want)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	struct a11y_key k = { .tgid = (__u32)(id >> 32), .code = BPF_CORE_READ(tr, code) };
	__u64 *cnt = bpf_map_lookup_elem(&a11y_counts, &k);
	if (cnt) {
		__sync_fetch_and_add(cnt, 1);
		return 0;
	}
	__u64 one = 1;
	bpf_map_update_elem(&a11y_counts, &k, &one, BPF_NOEXIST);

	struct accessibility_detect_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}
	e->h.type = MOD_EV_ACCESSIBILITY_DETECT;
	e->h.pid  = k.tgid;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;
	e->ts_ns  = bpf_ktime_get_ns();
	e->code   = k.code;
	e->_pad   = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
