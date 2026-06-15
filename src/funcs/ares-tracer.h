// SPDX-License-Identifier: GPL-2.0
#ifndef __ARES_TRACER_H
#define __ARES_TRACER_H

#define TASK_COMM_LEN    32
#define MAX_STR_LEN      128
#define NUM_ARGS         8
#define STACK_DEPTH      16
#define MAX_ARGV_ENTRIES 8
#define MAX_ARGV_STR     128


// Identifier for different event types
enum event_type {
    ARES_EVENT_CALL = 1,
    ARES_EVENT_MAP = 2,
    ARES_EVENT_RETURN = 3,
    ARES_EVENT_UNMAP = 4,
    ARES_EVENT_SPAWN = 5,
    ARES_EVENT_PROC_EXIT = 6,
    ARES_EVENT_EXECVE = 7,
    ARES_EVENT_PROP_READ = 8,  // __system_property_read_callback (per-property in foreach)
    ARES_EVENT_PROP_GET  = 9,  // __system_property_get  (CALL is_ret=0, RET is_ret=1)
    ARES_EVENT_PROP_FIND = 10, // __system_property_find (CALL is_ret=0, RET is_ret=1)
    ARES_EVENT_PROP_SCAN = 11, // __system_property_foreach (entry only)
};


// General header for events
struct event_header {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 _pad; // Padding for alignment based on recs 
};


// Event for native function calls (ARES_EVENT_CALL) and returns (ARES_EVENT_RETURN).
struct event {
    struct event_header h;
    __u64 entry_addr;
    __u64 caller_addr;    // x30 (LR) at function entry; unused in RETURN events
    __u64 elapsed_ns;     // time from entry to return (RETURN only; 0 in CALL)
    __u64 retval;         // return value register (RETURN only)
    int ppid;
    bool exit_event;      // true for RETURN events
    char comm[TASK_COMM_LEN];
    unsigned long args[NUM_ARGS];
    __u8 is_str[NUM_ARGS];
    char strings[NUM_ARGS][MAX_STR_LEN];
    __u64 call_stack[STACK_DEPTH];
    __u32 stack_depth;
};


// Event for process fork (ARES_EVENT_SPAWN).
struct spawn_event {
    struct event_header h;
    __u32 child_pid;
    char  comm[TASK_COMM_LEN];  // parent comm at fork time
};


// Event for process exit (ARES_EVENT_PROC_EXIT).
struct proc_exit_event {
    struct event_header h;
    char comm[TASK_COMM_LEN];
    int  exit_code;
};


// Event for execve syscall (ARES_EVENT_EXECVE).
struct execve_event {
    struct event_header h;
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
    struct event_header h;
    char  comm[TASK_COMM_LEN];
    char  name[PROP_NAME_LEN];
    char  value[PROP_VALUE_LEN];
    __u8  is_ret;    // 0 = call/entry, 1 = return
    __u8  found;     // PROP_FIND RET: 1 = property exists, 0 = not found
    __u8  _pad[2];
};


#endif /* __ARES_TRACER_H */