// syscalls.bpf.c
//
// Syscall tracer for a single Android app, filtered by native-library call
// origin. A syscall event is emitted only when the target library itself
// appears to be the issuer — the trap-PC frame or its immediate caller lands
// in one of the target library's executable ranges (e.g. a RASP/anti-tamper
// .so) — not merely present somewhere deeper on the call chain (CR2).
//
// Design notes (vs. the frida-strace lineage this is based on):
//
//   * Gating is by UID, not PID. The loader resolves the package's app-UID and
//     installs it BEFORE launching the app, so every thread of the freshly
//     forked app is traced from its very first syscall — closing the startup
//     gap that a launch-then-find-PID approach suffers from. Android sets the
//     app UID during zygote specialization, well before any app/native code
//     runs, so nothing the target library does is missed.
//
//   * The module map is built entirely from uprobe_mmap / uprobe_munmap events.
//     We never read /proc/<pid>/maps. As soon as the target library's text
//     segment is mapped, its mmap event is delivered to userspace, which arms
//     the range as soon as it's processed (syscalls.c). That processing is
//     asynchronous to the kernel-side mmap, so there IS a bounded pre-arm
//     window: a syscall the library issues before its range lands in
//     `lib_ranges` is dropped here rather than mis-filtered (CR2, COV_PREARM).
//
//   * Hook is a kprobe on do_el0_svc, the arm64 64-bit syscall dispatcher. This
//     kernel ships CONFIG_FTRACE_SYSCALLS=n on many builds, so we don't rely on
//     raw_syscalls:sys_enter. The syscall number is in x8, args in x0..x5, i.e.
//     the saved user pt_regs->regs[8] and regs[0..5].
//
//   * Entry-only. A kretprobe on do_el0_svc is exhausted by system-wide syscall
//     traffic (maxactive fills instantly), so return values are not captured.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "syscalls.h"
#include "syscalls/attribution.h"
#include "common/lib_trace.h"
#include "common/bpf_drop.bpf.h"
#include "common/coverage.bpf.h"

#define MAX_STACK_DEPTH SYSC_MAX_STACK_DEPTH

char LICENSE[] SEC("license") = "GPL";

// Set by the loader before load. 0 = only emit syscalls whose user stack passes
// through the target library; 1 = emit every syscall of the traced UID.
const volatile int capture_all = 0;

// Per-syscall allow/deny filter. 0 = off, 1 = allowlist (only flagged nrs),
// 2 = denylist (all except flagged). The flagged set lives in syscall_filter.
const volatile int syscall_filter_mode = 0;

// 1 = also capture a register set + bounded user-stack snapshot for each kept
// syscall (library-filtered mode only), deduped by stack signature, for
// off-device DWARF unwinding. The loader sets this; it is never on in
// capture-all mode (the snapshot is far too heavy for the firehose).
const volatile int snapshot_enabled = 0;

// ---- maps ----------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);                 // 4 MB
} events SEC(".maps");

#include "common/uid_filter.bpf.h"   // target_uids map + uid_matches()
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#define LIBTRACE_EXTRA_GATE() pid_matches()  // ponytail: opts in shared mmap probes to PID gate

// Per-process (keyed by tgid) executable ranges of the target library. The
// loader populates this in response to the mmap events we emit below.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct syscalls_lib_ranges);
} lib_ranges SEC(".maps");

// Per-syscall mask of which of args[0..3] are const char * (a string). Indexed
// by syscall number; filled by the loader from a built-in table. Used to decide
// which arguments to dereference and copy at entry.
#define ARG_TYPES_MAX 512
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ARG_TYPES_MAX);
	__type(key, __u32);
	__type(value, __u8);
} arg_types SEC(".maps");

// Per-syscall-number flag for the allow/deny filter (see syscall_filter_mode).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ARG_TYPES_MAX);
	__type(key, __u32);
	__type(value, __u8);
} syscall_filter SEC(".maps");

// Per-syscall: 1-based index of the sockaddr* argument (0 = none). Filled by the
// loader for connect/bind/sendto; the addrlen is the following argument.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ARG_TYPES_MAX);
	__type(key, __u32);
	__type(value, __u8);
} sock_args SEC(".maps");

// Threads (keyed by tid) with an in-flight syscall we emitted at entry and want
// the return value for. Set at do_el0_svc entry, consumed at __arm64_sys_*
// return. Bounded by live thread count.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} pending SEC(".maps");

// Stack signatures already snapshotted (dedup set for option A). LRU so a long
// run self-evicts; an eviction just causes one extra snapshot later (harmless).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u8);
} stack_seen SEC(".maps");

// ---- helpers -------------------------------------------------------------

// Apply the optional per-syscall allow/deny filter. Cheap — runs before the
// stack walk so unwanted syscalls cost almost nothing.
static __always_inline int syscall_wanted(__u64 nr)
{
	if (syscall_filter_mode == 0)
		return 1;
	__u32 k = (__u32)nr;
	if (k >= ARG_TYPES_MAX)
		return syscall_filter_mode == 2;       // out of range: kept only by denylist
	__u8 *v = bpf_map_lookup_elem(&syscall_filter, &k);
	__u8 flagged = v ? *v : 0;
	return (syscall_filter_mode == 1) ? flagged : !flagged;
}

// Shared snapshot BPF helpers (hash + emit) — pulled from common.
// ARES_SNAPSHOT_RB names the ringbuf this engine uses.
#define ARES_SNAPSHOT_RB events
#include "common/stack_snapshot.bpf.h"

// ---- syscall entry -------------------------------------------------------

SEC("kprobe/do_el0_svc")
int BPF_KPROBE(on_svc_enter, struct pt_regs *user_regs)
{
	if (!uid_matches() && !pid_matches())
		return 0;

	__u64 nr = BPF_CORE_READ(user_regs, regs[8]);
	if (!syscall_wanted(nr))
		return 0;

	__u64 id   = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;

	// Library-filter mode: with no target-library range armed for this process
	// yet, skip before paying for a stack walk. Usually the library really
	// isn't mapped yet; but it can also already be mapped in the kernel with its
	// range not yet armed here (the async kernel-mmap -> userspace-push hop
	// hasn't landed) — a real syscall from the library in that window is
	// dropped, not just cheaply skipped (CR2 pre-arm window). Capture-all mode
	// keeps every syscall regardless.
	struct syscalls_lib_ranges *lr = bpf_map_lookup_elem(&lib_ranges, &tgid);
	if (!capture_all && (!lr || lr->count == 0)) {
		cov_bump(COV_PREARM);
		return 0;
	}

	__u64 stack[MAX_STACK_DEPTH];
	long sz = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);
	// Unsigned division (guarded by sz > 0) so the BPF backend lowers it to a
	// shift; a signed div by a power of two is rejected by older clang (<=14).
	int n = sz > 0 ? (int)((__u64)sz / sizeof(__u64)) : 0;
	// Buffer saturated: the true stack may be deeper than MAX_STACK_DEPTH, so
	// the raw backtrace shipped in the event (and any CFI-unwind snapshot built
	// from it) may be incomplete. Independent of attribution below, which only
	// ever looks at stack[0]/stack[1].
	if (n >= MAX_STACK_DEPTH)
		cov_bump(COV_DEPTH_CAP);

	if (!capture_all) {
		if (sz <= 0)
			return 0;
		if (!sysc_issuer_hit(lr, stack, n))
			return 0;
	}

	// Stack snapshot (option A dedup): the first time we see a given stack for
	// this process, ship its registers + stack bytes for off-device unwinding;
	// thereafter the syscall event just carries the stack_id. Filtered mode only
	// (snapshot_enabled is never set in capture-all).
	__u64 stack_id = 0;
	if (snapshot_enabled && sz > 0) {
		stack_id = ares_hash_stack(stack, n, tgid, MAX_STACK_DEPTH);
		if (!bpf_map_lookup_elem(&stack_seen, &stack_id)) {
			__u8 one = 1;
			bpf_map_update_elem(&stack_seen, &stack_id, &one, BPF_ANY);
			ares_emit_stack_snapshot(user_regs, tgid, (__u32)id, stack_id, SYSC_EV_STACK);
		}
	}

	// EPIC C3: this kprobe captures no clock today - the cross-engine
	// chronological join key. Read here, right before the reserve, same
	// placement as correlate's mirror of this same probe (corr_on_svc).
	__u64 ktime = bpf_ktime_get_ns();

	struct syscalls_syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}

	e->h.type = SYSC_EV_SYSCALL;
	e->h.pid  = tgid;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;

	e->nr      = nr;
	e->ktime   = ktime;
	e->compat  = 0;
	e->args[0] = BPF_CORE_READ(user_regs, regs[0]);
	e->args[1] = BPF_CORE_READ(user_regs, regs[1]);
	e->args[2] = BPF_CORE_READ(user_regs, regs[2]);
	e->args[3] = BPF_CORE_READ(user_regs, regs[3]);
	e->args[4] = BPF_CORE_READ(user_regs, regs[4]);
	e->args[5] = BPF_CORE_READ(user_regs, regs[5]);
	e->stack_id = stack_id;
	if (sz > 0) {
		e->stack_sz = (__s32)sz;
		__builtin_memcpy(e->stack, stack, sizeof(e->stack));
	} else {
		e->stack_sz = 0;
		__builtin_memset(e->stack, 0, sizeof(e->stack));
	}

	// Resolve string arguments. Look up which of args[0..3] are char* for this
	// syscall and copy the pointed-to string out of the caller's memory. The
	// loop is unrolled so each e->str[i] is a constant offset (verifier-safe).
	e->str_present = 0;
	__u32 nr32 = (__u32)e->nr;
	__u8 *maskp = (nr32 < ARG_TYPES_MAX) ? bpf_map_lookup_elem(&arg_types, &nr32) : NULL;
	__u8 mask = maskp ? *maskp : 0;
	if (mask) {
		#pragma clang loop unroll(full)
		for (int i = 0; i < SYSC_STR_SLOTS; i++) {
			if (!((mask >> i) & 1))
				continue;
			long r = bpf_probe_read_user_str(e->str[i], SYSC_STR_MAX,
							 (const void *)e->args[i]);
			if (r > 0)
				e->str_present |= (1u << i);
			else
				e->str[i][0] = '\0';
		}
	}

	// Capture the sockaddr for connect/bind/sendto. sock_args[nr] holds the
	// 1-based index of the sockaddr* arg; the addrlen is the next arg. The args
	// array is indexed with constant offsets (unrolled) so the verifier keeps the
	// bounds — a runtime index into e->args is rejected.
	e->sock_len = 0;
	__u8 *sap = (nr32 < ARG_TYPES_MAX) ? bpf_map_lookup_elem(&sock_args, &nr32) : NULL;
	__u8 sidx = sap ? *sap : 0;
	if (sidx) {
		const void *ptr = NULL;
		__u64 alen = 0;
		#pragma clang loop unroll(full)
		for (int j = 0; j < SYSC_SYSCALL_NARGS - 1; j++) {
			if (sidx == (__u8)(j + 1)) {
				ptr = (const void *)e->args[j];
				alen = e->args[j + 1];
			}
		}
		if (ptr && alen) {
			// Mask rather than clamp so the bound is on the exact size register
			// the verifier checks (a conditional clamp left an unbounded copy).
			// sock[] is SYSC_SOCK_MAX (a power of two); never reads > alen.
			__u32 cnt = (__u32)alen & (SYSC_SOCK_MAX - 1);
			if (cnt && bpf_probe_read_user(e->sock, cnt, ptr) == 0)
				e->sock_len = cnt;
		}
	}

	bpf_ringbuf_submit(e, 0);

	// Mark this thread so the return probe knows to emit this syscall's result.
	__u32 tid32 = (__u32)id;
	bpf_map_update_elem(&pending, &tid32, &nr, BPF_ANY);
	return 0;
}

// ---- syscall entry (32-bit / AArch32 compat) ------------------------------
//
// AArch32 (EABI) app code traps through do_el0_svc_compat, not do_el0_svc, with
// the syscall number in r7 (not x8) and args in r0..r5 — same slots, different
// register file. EABI syscall numbers are also a wholly different namespace
// from arm64's, so this program deliberately does NOT reuse anything keyed on
// the arm64 nr: no -s/-x allow/denylist (syscall_filter), no string-arg or
// sockaddr capture (arg_types/sock_args), no return-value pairing (the
// kretprobe.multi list below attaches to __arm64_sys_* symbols, which compat
// calls never pass through). Attribution (sysc_issuer_hit), the pre-arm gate,
// and stack-snapshot dedup are namespace-agnostic and reused as-is. Closes
// CR2's 32-bit blind spot; userspace renders these numerically (no EABI name
// table — see sysname() in syscalls.c).
SEC("kprobe/do_el0_svc_compat")
int BPF_KPROBE(on_svc_enter_compat, struct pt_regs *user_regs)
{
	if (!uid_matches() && !pid_matches())
		return 0;

	__u64 nr = BPF_CORE_READ(user_regs, regs[7]);   // EABI: syscall nr in r7

	__u64 id   = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;

	// Same pre-arm gate as the 64-bit path (see on_svc_enter for the CR2 caveat).
	struct syscalls_lib_ranges *lr = bpf_map_lookup_elem(&lib_ranges, &tgid);
	if (!capture_all && (!lr || lr->count == 0)) {
		cov_bump(COV_PREARM);
		return 0;
	}

	__u64 stack[MAX_STACK_DEPTH];
	long sz = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);
	int n = sz > 0 ? (int)((__u64)sz / sizeof(__u64)) : 0;
	if (n >= MAX_STACK_DEPTH)
		cov_bump(COV_DEPTH_CAP);

	if (!capture_all) {
		if (sz <= 0)
			return 0;
		if (!sysc_issuer_hit(lr, stack, n))
			return 0;
	}

	__u64 stack_id = 0;
	if (snapshot_enabled && sz > 0) {
		stack_id = ares_hash_stack(stack, n, tgid, MAX_STACK_DEPTH);
		if (!bpf_map_lookup_elem(&stack_seen, &stack_id)) {
			__u8 one = 1;
			bpf_map_update_elem(&stack_seen, &stack_id, &one, BPF_ANY);
			ares_emit_stack_snapshot(user_regs, tgid, (__u32)id, stack_id, SYSC_EV_STACK);
		}
	}

	// EPIC C3: same new capture as the 64-bit path above (on_svc_enter).
	__u64 ktime = bpf_ktime_get_ns();

	struct syscalls_syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}

	e->h.type = SYSC_EV_SYSCALL;
	e->h.pid  = tgid;
	e->h.tid  = (__u32)id;
	e->h._pad = 0;

	e->nr      = nr;
	e->ktime   = ktime;
	e->compat  = 1;
	e->args[0] = BPF_CORE_READ(user_regs, regs[0]);
	e->args[1] = BPF_CORE_READ(user_regs, regs[1]);
	e->args[2] = BPF_CORE_READ(user_regs, regs[2]);
	e->args[3] = BPF_CORE_READ(user_regs, regs[3]);
	e->args[4] = BPF_CORE_READ(user_regs, regs[4]);
	e->args[5] = BPF_CORE_READ(user_regs, regs[5]);
	e->stack_id = stack_id;
	if (sz > 0) {
		e->stack_sz = (__s32)sz;
		__builtin_memcpy(e->stack, stack, sizeof(e->stack));
	} else {
		e->stack_sz = 0;
		__builtin_memset(e->stack, 0, sizeof(e->stack));
	}
	// EABI nr namespace: arg_types/sock_args are arm64-keyed, so string and
	// sockaddr capture are intentionally skipped here (see comment above).
	e->str_present = 0;
	e->sock_len = 0;

	bpf_ringbuf_submit(e, 0);

	// No pending-map entry: there is no kretprobe attached to any compat
	// syscall implementation, so nothing would ever consume it.
	return 0;
}

// ---- syscall return ------------------------------------------------------
//
// One classic kretprobe program, attached by the loader to a curated list of
// __arm64_sys_* implementation functions (kretprobe.multi/fprobe needs the
// ftrace function tracer, which many Android kernels omit — no
// available_filter_functions). Attaching per-function keeps each function's
// kretprobe instance pool independent, so it avoids the maxactive exhaustion a
// kretprobe on the shared do_el0_svc dispatcher would hit. Gated by the per-tid
// `pending` flag so we only emit returns for syscalls we kept. The SEC target is
// just a placeholder; the loader disables autoattach and attaches the real list.

SEC("kretprobe/__arm64_sys_openat")
int BPF_KRETPROBE(on_sys_exit, long ret)
{
	__u64 id  = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;

	__u64 *p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return 0;
	bpf_map_delete_elem(&pending, &tid);

	struct syscalls_return_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump_dropped();
		return 0;
	}

	e->h.type = SYSC_EV_RETURN;
	e->h.pid  = id >> 32;
	e->h.tid  = tid;
	e->h._pad = 0;
	e->retval = ret;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- module map: mmap / munmap of executable file mappings ---------------
//
// Shared capture (common/lib_trace.bpf.h) emits lib_map_event / lib_unmap_event
// into `events`. syscalls numbers UNMAP as 3 (RETURN is 4), so map the shared
// discriminators onto its enum, and route dropped reservations to bump_dropped().
#define LIBTRACE_TYPE_MAP   SYSC_EV_MAP
#define LIBTRACE_TYPE_UNMAP SYSC_EV_UNMAP
#define LIBTRACE_ON_DROP()  bump_dropped()
#include "common/lib_trace.bpf.h"
