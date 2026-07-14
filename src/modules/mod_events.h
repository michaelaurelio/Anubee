// SPDX-License-Identifier: GPL-2.0
// Shared event structs for the ares mod analyzers. Included by both BPF
// programs (after vmlinux.h, before any libc headers) and userspace analyzer
// files. Must NOT pull <linux/types.h> or libc headers — vmlinux.h already
// provides __u32/__u64; userspace callers include <linux/types.h> first.
//
// MOD_EV_* are BPF-side type tags local to the analyzers. Userspace emitters
// map them to TRACE_* (trace_schema.h) for the stable output schema.
#ifndef __ARES_MOD_EVENTS_H
#define __ARES_MOD_EVENTS_H

#include "common/trace_schema.h"   // struct trace_event_header, TRACE_*

#define TASK_COMM_LEN    32
#define MAX_ARGV_ENTRIES  8
#define MAX_ARGV_STR    128
#define STACK_DEPTH      16
#define PROP_NAME_LEN   128
#define PROP_VALUE_LEN   96
#define FILE_PATH_LEN   256
// RING_LEN > THRESHOLD is load-bearing (see massdelete_detect.bpf.c): the
// per-pid hash ring never wraps before a window resets, so at emit time the
// first `touch_count` ring slots are always exactly this window's hashes --
// no stale cross-window data, no wraparound bookkeeping needed. RING_LEN must
// also stay a power of two: the slot index is computed with a `& (RING_LEN-1)`
// mask (not `%`) because the BPF verifier can prove a constant-mask AND is
// bounded but can't range-track a non-power-of-2 modulo's multiply/shift
// codegen -- confirmed on-device (-EACCES "unbounded memory access" at 24).
#define MASSDELETE_DETECT_RING_LEN 32
#define MASSDELETE_DETECT_THRESHOLD           20

// Per-pid sliding-window burst counter for mod a11y-abuse (see
// a11y_abuse.bpf.c). Same load-bearing relationship as
// MASSDELETE_DETECT_RING_LEN/MASSDELETE_DETECT_THRESHOLD above: the ring must never wrap
// before a window resets (RING_LEN > THRESHOLD), and the slot index uses a
// `& (RING_LEN-1)` mask, so RING_LEN must stay a power of two (the BPF
// verifier can't range-track a non-pow2 modulo).
#define A11Y_CODE_RING_LEN 64
#define A11Y_THRESHOLD     50

// Truncated capture buffer for the fileless-exec analyzer's anon_name field
// (see fileless_exec.bpf.c). Not a ring/threshold pair like the burst
// analyzers above -- this is a single fixed-size string buffer, sized to
// comfortably hold ART's own tags (e.g. "dalvik-jit-code-cache" is 22
// bytes) plus headroom for whatever a non-ART caller might have set.
#define FILELESS_TAG_LEN 32

// Grace window between an anon+exec mmap candidate landing in pending_map
// and (absent a suppressing dalvik-tagged prctl) graduating into an alert.
// See fileless_exec.bpf.c's two-hook mmap+prctl correlate/suppress design.
#define FILELESS_GRACE_NS (250ULL * 1000000ULL)

// BPF map key/value for fileless-exec's pending-alert map: mmap-time state
// that gets suppressed if a matching dalvik-tagged
// prctl(PR_SET_VMA_ANON_NAME) follows within FILELESS_GRACE_NS, or
// graduates into an alert if not. Shared between fileless_exec.bpf.c
// (writer, both hooks) and fileless_exec.c (background-thread reader).
struct fileless_pending_key {
    __u32 pid;
    __u32 _pad;
    __u64 addr;
};

struct fileless_pending_val {
    __u64 ts_ns;
    __u64 size;
    char  comm[TASK_COMM_LEN];
};

// BPF-side event type discriminators (set in h.type by each .bpf.c program).
enum {
    MOD_EV_SPAWN      = 1,
    MOD_EV_PROC_EXIT  = 2,
    MOD_EV_EXECVE     = 3,
    MOD_EV_PROP_GET   = 4,
    MOD_EV_PROP_FIND  = 5,
    MOD_EV_PROP_SCAN  = 6,
    MOD_EV_PROP_READ  = 7,
    MOD_EV_FILE_ACCESS = 8,
    MOD_EV_MASSDELETE_DETECT = 9,
    MOD_EV_EXFIL_BURST = 10,
    MOD_EV_A11Y_ABUSE = 11,
    MOD_EV_FILELESS_EXEC = 12,
    MOD_EV_MEDIAPROJ_ABUSE = 13,
};

struct spawn_event {
    struct trace_event_header h;
    __u64 ts_ns;
    __u32 child_pid;
    char  comm[TASK_COMM_LEN];
};

struct proc_exit_event {
    struct trace_event_header h;
    __u64 ts_ns;
    char comm[TASK_COMM_LEN];
    int  exit_code;
};

struct execve_event {
    struct trace_event_header h;
    __u64 ts_ns;
    __u32 argc;
    __u32 stack_depth;
    char  comm[TASK_COMM_LEN];
    char  filename[128];
    char  argv[MAX_ARGV_ENTRIES][MAX_ARGV_STR];
    __u64 call_stack[STACK_DEPTH];
};

struct prop_event {
    struct trace_event_header h;
    __u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char name[PROP_NAME_LEN];
    char value[PROP_VALUE_LEN];
    __u8 is_ret;
    __u8 found;
    __u8 _pad[2];
};

struct file_access_event {
    struct trace_event_header h;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
    char  path[FILE_PATH_LEN];
    __u32 flags;
    __u8  _pad[4];
};

struct massdelete_detect_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u32  touch_count;
    __u32  window_ms;
    __u64  path_hashes[MASSDELETE_DETECT_RING_LEN];
    char   sample_path[FILE_PATH_LEN];
};

struct exfil_burst_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u64  bytes_sent;
    __u32  window_ms;
    char   sample_path[FILE_PATH_LEN];
    unsigned char dest[28];   // raw sockaddr bytes (sockaddr_in6-sized), or all-zero
    __u32  dest_len;          // 0 if no connect() was observed before threshold
};

struct a11y_abuse_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u32  touch_count;
    __u32  window_ms;
    __u32  code_samples[A11Y_CODE_RING_LEN];
};

struct fileless_exec_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u64  start;
    __u64  size;
    char   anon_name[FILELESS_TAG_LEN];
};

struct mediaproj_abuse_event {
    struct trace_event_header h;
    __u64  ts_ns;
    char   comm[TASK_COMM_LEN];
    __u64  binder_calls_context;
};

#endif /* __ARES_MOD_EVENTS_H */
