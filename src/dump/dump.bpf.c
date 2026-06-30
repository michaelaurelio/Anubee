// SPDX-License-Identifier: GPL-2.0
// BPF object for `ares dump`: trace every native library (.so) an app loads so
// the loader can dump matching modules from live memory.
//
// Per-engine BPF (detectability firewall): this is its own object, not the
// uprobe engine's. Gating is by UID (common/uid_filter.bpf.h), installed by the
// loader BEFORE launch, so every thread of the freshly forked app is seen from
// its first mapping. The mmap/munmap capture is common/lib_trace.bpf.h.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common/lib_trace.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);                 // 4 MB
} events SEC(".maps");

#include "common/uid_filter.bpf.h"   // target_uids map + uid_matches()
#include "common/pid_filter.bpf.h"
#include "common/follow_fork.bpf.h"
#define LIBTRACE_EXTRA_GATE() pid_matches()
#include "common/lib_trace.bpf.h"
