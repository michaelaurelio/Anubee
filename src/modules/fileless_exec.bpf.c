// SPDX-License-Identifier: GPL-2.0
// BPF object for the fileless-exec analyzer: flag anonymous (no backing
// file) executable memory mappings that aren't one of ART's own JIT/zygote
// regions. This is the mechanism behind native packers/unpackers and
// multi-stage droppers that hand off to a second-stage payload without ever
// writing it to disk (e.g. NexusRoute's obfuscated native-library-via-JNI
// handoff stage) -- not DexClassLoader/DEX loading, which executes through
// ART's own (carved-out) JIT cache rather than a raw anonymous mapping. v1
// is mmap-only, no mprotect/memfd coverage (parked, see
// docs/superpowers/specs/2026-07-12-mod-fileless-exec-design.md).
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

// Revision 1: kprobe/uprobe_mmap never fires for anonymous (vm_file==NULL)
// mappings -- confirmed on-device and via kernel source, see the design
// doc's Revision 1 section. Corrected mechanism: do_mmap entry+return
// (fires for every mmap, file-backed or not) records a candidate into
// pending_map; a separate __arm64_sys_prctl hook deletes (suppresses) the
// candidate if a matching dalvik-tagged prctl(PR_SET_VMA_ANON_NAME) call
// follows shortly after (ART's own JIT-cache naming is a distinct, later
// syscall -- confirmed via ART source, so no single mmap-time hook could
// ever see the name). Userspace (fileless_exec.c) polls pending_map on a
// background thread and alerts on anything that survives the grace window
// unsuppressed. No ringbuf event is written by either hook.

#define FILELESS_PROT_EXEC 0x4UL   // PROT_EXEC, from <sys/mman.h> -- do_mmap's
                                   // prot arg uses the same userspace-facing bit values

// PR_SET_VMA / PR_SET_VMA_ANON_NAME, from <linux/prctl.h> -- not exposed via
// vmlinux.h (these are #define constants, not BTF-visible), so hardcoded
// here with the header reference for provenance. Re-verify these two
// values first if on-device suppression testing doesn't behave as expected.
#define FILELESS_PR_SET_VMA           0x53564d41UL  // "SVMA" -- PR_SET_VMA
#define FILELESS_PR_SET_VMA_ANON_NAME 0UL            // PR_SET_VMA_ANON_NAME

// Per-tid scratch: do_mmap's real args, captured at entry and consumed at
// return -- a kretprobe alone can't see entry args (registers are
// clobbered by the callee), same reasoning as every other entry/exit
// correlation map in this codebase.
struct fileless_entry_scratch {
    __u64 len;
    __u32 anon;   // 1 if file == NULL at entry, else 0
    __u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);                          // pid_tgid
	__type(value, struct fileless_entry_scratch);
} entry_scratch SEC(".maps");

// Candidate anon+exec mappings awaiting either suppression (dalvik-tagged
// prctl arrives) or graduation into an alert (userspace background thread
// reads FILELESS_GRACE_NS-old entries that are still present). No ringbuf
// traffic -- this map IS the signal path. At capacity (1024), a new
// candidate is silently not inserted (BPF_MAP_TYPE_HASH has no eviction) --
// accepted v1 gap, see design doc's Known limitations.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct fileless_pending_key);
	__type(value, struct fileless_pending_val);
} pending_map SEC(".maps");

SEC("kprobe/do_mmap")
int BPF_KPROBE(on_do_mmap_entry, struct file *file, unsigned long addr,
               unsigned long len, unsigned long prot, unsigned long flags)
{
    if (!uid_matches() && !pid_matches())
        return 0;
    if (!(prot & FILELESS_PROT_EXEC))
        return 0;

    struct fileless_entry_scratch sc = {
        .len  = len,
        .anon = (file == NULL) ? 1u : 0u,
    };
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&entry_scratch, &id, &sc, BPF_ANY);
    return 0;
}

SEC("kretprobe/do_mmap")
int BPF_KRETPROBE(on_do_mmap_exit, long ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct fileless_entry_scratch *sc = bpf_map_lookup_elem(&entry_scratch, &id);
    if (!sc)
        return 0;
    struct fileless_entry_scratch local = *sc;
    bpf_map_delete_elem(&entry_scratch, &id);   // always clear scratch, hit or miss

    if (!local.anon || ret <= 0)
        return 0;

    struct fileless_pending_key k = {
        .pid  = (__u32)(id >> 32),
        .addr = (__u64)ret,
    };
    struct fileless_pending_val v = {
        .ts_ns = bpf_ktime_get_ns(),
        .size  = local.len,
    };
    bpf_get_current_comm(&v.comm, sizeof(v.comm));
    bpf_map_update_elem(&pending_map, &k, &v, BPF_ANY);
    return 0;
}

// prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, name) -- ART's own
// JIT/zygote naming call, a distinct syscall from the mmap that created the
// region. Syscall-entry kprobe, args from pt_regs (same idiom as
// execve.bpf.c's on_execve: regs->regs[0..4], MTE-tag-stripped before any
// user pointer read).
SEC("kprobe/__arm64_sys_prctl")
int BPF_KPROBE(on_prctl, const struct pt_regs *regs)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    unsigned long option = BPF_CORE_READ(regs, regs[0]);
    if (option != FILELESS_PR_SET_VMA)
        return 0;
    unsigned long subop = BPF_CORE_READ(regs, regs[1]);
    if (subop != FILELESS_PR_SET_VMA_ANON_NAME)
        return 0;

    unsigned long addr     = BPF_CORE_READ(regs, regs[2]);
    unsigned long name_ptr = BPF_CORE_READ(regs, regs[4]) & 0x00FFFFFFFFFFFFFFul;

    char tag[FILELESS_TAG_LEN] = {0};
    bpf_probe_read_user_str(tag, sizeof(tag), (void *)name_ptr);
    if (!(tag[0] == 'd' && tag[1] == 'a' && tag[2] == 'l' && tag[3] == 'v'
          && tag[4] == 'i' && tag[5] == 'k'))
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    struct fileless_pending_key k = {
        .pid  = (__u32)(id >> 32),
        .addr = (__u64)addr,
    };
    bpf_map_delete_elem(&pending_map, &k);   // suppress: never alerted if present
    return 0;
}
