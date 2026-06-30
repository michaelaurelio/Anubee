// SPDX-License-Identifier: GPL-2.0
// BPF object for `ares lib`: trace every native library (.so) an app loads.
//
// Gating is by UID, installed by the loader BEFORE the app is launched, so every
// thread of the freshly forked app is seen from its first mapping (same approach
// as the syscalls engine). The actual mmap/munmap capture is the shared probe in
// common/lib_trace.bpf.h — this file only supplies the ring buffer and includes
// the shared UID filter (common/uid_filter.bpf.h).
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
#define LIBTRACE_EXTRA_GATE() pid_matches()  // ponytail: opts in shared mmap probes to PID gate
#include "common/lib_trace.bpf.h"
