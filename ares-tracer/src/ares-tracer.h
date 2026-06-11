#ifndef __ARES_TRACER_H
#define __ARES_TRACER_H

#define TASK_COMM_LEN 32
#define MAX_STR_LEN 128
#define NUM_ARGS    8
#define STACK_DEPTH 16

#define ARES_VM_EXEC 0x00000004UL // Linux VMA flag for executable mappings


// Identifier for different event types 
enum event_type {
    ARES_EVENT_CALL = 1,
    ARES_EVENT_MAP = 2,
    ARES_EVENT_RETURN = 3, 
    ARES_EVENT_UNMAP = 4,
};


// General header for events
struct event_header {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 _pad; // Padding for alignment based on recs 
};


// Event for native function calls (ARES_EVENT_CALL) and returns (ARES_EVENT_RETURN).
//
// RETURN layout differs from CALL:
//   retval        = PT_REGS_RC (raw return value)
//   elapsed_ns    = ns from entry to return (0 in CALL events)
//   is_str[0]     = 1 if retval is a valid string pointer and was read into strings[0]
//   strings[0]    = retval read as string (if is_str[0])
//   args[i+1]     = saved entry arg[i] pointer (for output buffer re-read), i=0..6
//   is_str[i+1]   = 1 if re-read of entry arg[i] produced a string
//   strings[i+1]  = re-read string content of entry arg[i]
//
// TID-keyed entry_map limitation: nested calls to two different tracked functions on the
// same thread will corrupt correlation — the inner entry overwrites the outer's saved data.
// Acceptable for RASP analysis (functions don't nest this way in practice). Future fix:
// key by (TID, lower-N-bits-of-entry_addr) or use a per-TID call stack in the map.
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


// Event for module mapping
struct map_event {
	struct event_header h;
	__u64 start;
	__u64 end;
	__u64 pgoff;                                 // file offset in pages 
	__u64 vm_flags;
	__u64 inode;
	__u32 dev;
	char name[MAX_STR_LEN];               // mapped file basename
};


#endif /* __ARES_TRACER_H */