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

// Linux VMA flag for executable mappings. Same value as lib_trace.h's
// LIBTRACE_VM_EXEC; kept as a local constant rather than pulling in
// lib_trace.h, since this analyzer's gate is the semantic inverse (pure
// anonymous, not file-backed) and shares no other code with it.
#define FILELESS_VM_EXEC 0x00000004UL

SEC("kprobe/uprobe_mmap")
int BPF_KPROBE(on_uprobe_mmap, struct vm_area_struct *vma)
{
    if (!uid_matches() && !pid_matches())
        return 0;

    struct file *file = BPF_CORE_READ(vma, vm_file);
    if (file != NULL)
        return 0;                              // v1: pure anonymous only

    __u64 vm_flags = BPF_CORE_READ(vma, vm_flags);
    if (!(vm_flags & FILELESS_VM_EXEC))
        return 0;

    char tag[FILELESS_TAG_LEN] = {0};
    struct anon_vma_name *an = BPF_CORE_READ(vma, anon_name);
    if (an) {
        bpf_probe_read_kernel_str(tag, sizeof(tag), an->name);
        // ART tags its own JIT/zygote anonymous regions with a "dalvik-"
        // prefix via prctl(PR_SET_VMA_ANON_NAME) -- every app's legitimate
        // JIT code cache carries this tag. Byte compare (not
        // bpf_strncmp/memcmp) to avoid a helper that may not exist on all
        // target kernel versions.
        if (tag[0] == 'd' && tag[1] == 'a' && tag[2] == 'l' && tag[3] == 'v'
            && tag[4] == 'i' && tag[5] == 'k')
            return 0;
    }

    struct fileless_exec_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        bump_dropped();
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    e->h.type = MOD_EV_FILELESS_EXEC;
    e->h.pid  = (__u32)(id >> 32);
    e->h.tid  = (__u32)id;
    e->h._pad = 0;
    e->start  = BPF_CORE_READ(vma, vm_start);
    e->size   = BPF_CORE_READ(vma, vm_end) - e->start;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->anon_name, tag, sizeof(tag));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
