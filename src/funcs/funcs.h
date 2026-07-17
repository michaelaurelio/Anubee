// SPDX-License-Identifier: GPL-2.0
#ifndef __FUNCS_H
#define __FUNCS_H

#define TASK_COMM_LEN    32
#define MAX_STR_LEN      128
#define SOCK_ADDR_MAX    28   // AF_INET6 sockaddr is 28 B; AF_INET is 16
#define NUM_ARGS         8
#define STACK_DEPTH      16
#define MAX_ARGV_ENTRIES 8
#define MAX_ARGV_STR     128


// Identifier for different event types
enum event_type {
    ANUBEE_EVENT_CALL = 1,
    ANUBEE_EVENT_MAP = 2,
    ANUBEE_EVENT_RETURN = 3,
    ANUBEE_EVENT_UNMAP = 4,
    ANUBEE_EVENT_SPAWN = 5,
    ANUBEE_EVENT_PROC_EXIT = 6,
    ANUBEE_EVENT_EXECVE = 7,
    ANUBEE_EVENT_PROP_READ = 8,  // __system_property_read_callback (per-property in foreach)
    ANUBEE_EVENT_PROP_GET  = 9,  // __system_property_get  (CALL is_ret=0, RET is_ret=1)
    ANUBEE_EVENT_PROP_FIND = 10, // __system_property_find (CALL is_ret=0, RET is_ret=1)
    ANUBEE_EVENT_PROP_SCAN = 11, // __system_property_foreach (entry only)
    ANUBEE_EVENT_STACK     = 12, // stack snapshot sidecar (first sight of each distinct stack)
};


#include "common/trace_schema.h"

// Event for native function calls (ANUBEE_EVENT_CALL) and returns (ANUBEE_EVENT_RETURN).
struct event {
    struct trace_event_header h;
    __u64 entry_addr;
    __u64 caller_addr;    // x30 (LR) at function entry; unused in RETURN events
    __u64 elapsed_ns;     // time from entry to return (RETURN only; 0 in CALL)
    __u64 ktime;          // boot-monotonic ns at this event (bpf_ktime_get_ns) - entry
                           // time for CALL, return time for RETURN; the cross-engine
                           // chronological join key (EPIC C3)
    __u64 retval;         // return value register (RETURN only)
    int ppid;
    bool exit_event;      // true for RETURN events
    char comm[TASK_COMM_LEN];
    unsigned long args[NUM_ARGS];
    __u8 is_str[NUM_ARGS];
    char strings[NUM_ARGS][MAX_STR_LEN];
    __u8 sock[NUM_ARGS][SOCK_ADDR_MAX];  // raw sockaddr bytes for ARG_SOCKADDR args (see funcs.bpf.c sockaddr_capture)
    __u64 call_stack[STACK_DEPTH];
    __u32 stack_depth;
    __u64 stack_id;   /* FNV-1a hash of call_stack; 0 = none. Links to ANUBEE_EVENT_STACK sidecar. */
    __u64 span_id;    /* monotonic per-call span id; emitted as "id". A CALL and its RETURN share it
                         (pairs the two records + orders the stream, like syscalls' "id"). 0 = the
                         span-depth cap was hit at entry, so this call is untracked/unpaired. */
};


// Event for process fork (ANUBEE_EVENT_SPAWN).
struct spawn_event {
    struct trace_event_header h;
    __u32 child_pid;
    char  comm[TASK_COMM_LEN];  // parent comm at fork time
};


// Event for process exit (ANUBEE_EVENT_PROC_EXIT).
struct proc_exit_event {
    struct trace_event_header h;
    char comm[TASK_COMM_LEN];
    int  exit_code;
};


// Event for execve syscall (ANUBEE_EVENT_EXECVE).
struct execve_event {
    struct trace_event_header h;
    __u32 argc;
    __u32 stack_depth;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_STR_LEN];
    char  argv[MAX_ARGV_ENTRIES][MAX_ARGV_STR];
    __u64 call_stack[STACK_DEPTH];
};


// Unified event struct for all system property API hooks (PROP_READ, PROP_GET, PROP_FIND, PROP_SCAN).
#define PROP_NAME_LEN  128
#define PROP_VALUE_LEN  96

struct prop_event {
    struct trace_event_header h;
    char  comm[TASK_COMM_LEN];
    char  name[PROP_NAME_LEN];
    char  value[PROP_VALUE_LEN];
    __u8  is_ret;    // 0 = call/entry, 1 = return
    __u8  found;     // PROP_FIND RET: 1 = property exists, 0 = not found
    __u8  _pad[2];
};


#endif /* __FUNCS_H */