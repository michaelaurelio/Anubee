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
// RING_LEN > THRESHOLD is load-bearing (see ransomware_burst.bpf.c): the
// per-pid hash ring never wraps before a window resets, so at emit time the
// first `touch_count` ring slots are always exactly this window's hashes --
// no stale cross-window data, no wraparound bookkeeping needed. RING_LEN must
// also stay a power of two: the slot index is computed with a `& (RING_LEN-1)`
// mask (not `%`) because the BPF verifier can prove a constant-mask AND is
// bounded but can't range-track a non-power-of-2 modulo's multiply/shift
// codegen -- confirmed on-device (-EACCES "unbounded memory access" at 24).
#define RANSOMWARE_BURST_RING_LEN 32
#define BURST_THRESHOLD           20

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
    MOD_EV_RANSOMWARE_BURST = 9,
    MOD_EV_EXFIL_BURST = 10,
};

struct spawn_event {
    struct trace_event_header h;
    __u32 child_pid;
    char  comm[TASK_COMM_LEN];
};

struct proc_exit_event {
    struct trace_event_header h;
    char comm[TASK_COMM_LEN];
    int  exit_code;
};

struct execve_event {
    struct trace_event_header h;
    __u32 argc;
    __u32 stack_depth;
    char  comm[TASK_COMM_LEN];
    char  filename[128];
    char  argv[MAX_ARGV_ENTRIES][MAX_ARGV_STR];
    __u64 call_stack[STACK_DEPTH];
};

struct prop_event {
    struct trace_event_header h;
    char comm[TASK_COMM_LEN];
    char name[PROP_NAME_LEN];
    char value[PROP_VALUE_LEN];
    __u8 is_ret;
    __u8 found;
    __u8 _pad[2];
};

struct file_access_event {
    struct trace_event_header h;
    char  comm[TASK_COMM_LEN];
    char  path[FILE_PATH_LEN];
    __u32 flags;
    __u8  _pad[4];
};

struct ransomware_burst_event {
    struct trace_event_header h;
    char   comm[TASK_COMM_LEN];
    __u32  touch_count;
    __u32  window_ms;
    __u64  path_hashes[RANSOMWARE_BURST_RING_LEN];
    char   sample_path[FILE_PATH_LEN];
};

struct exfil_burst_event {
    struct trace_event_header h;
    char   comm[TASK_COMM_LEN];
    __u64  bytes_sent;
    __u32  window_ms;
    char   sample_path[FILE_PATH_LEN];
    unsigned char dest[28];   // raw sockaddr bytes (sockaddr_in6-sized), or all-zero
    __u32  dest_len;          // 0 if no connect() was observed before threshold
};

#endif /* __ARES_MOD_EVENTS_H */
