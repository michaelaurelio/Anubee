#ifndef __ARES_TRACER_H
#define __ARES_TRACER_H

#define TASK_COMM_LEN    32
#define MAX_STR_LEN      128
#define NUM_ARGS         8
#define STACK_DEPTH      16
#define MAX_ARGV_ENTRIES 8
#define MAX_ARGV_STR     64

#define ARES_VM_EXEC 0x00000004UL // Linux VMA flag for executable mappings


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
	int   ppid;
	char name[MAX_STR_LEN];               // mapped file basename
};


// Event for process fork (ARES_EVENT_SPAWN).
// h.pid = parent TGID; child_pid = new process/thread TID.
// Note: thread creation via clone() also fires this event.
struct spawn_event {
    struct event_header h;
    __u32 child_pid;
    char  comm[TASK_COMM_LEN];  // parent comm at fork time
};


// Event for process exit (ARES_EVENT_PROC_EXIT).
// Only emitted for the main thread (pid == tid); thread exits are suppressed.
// exit_code encoding: signal = exit_code & 0x7f (non-zero = killed);
//                     status = (exit_code >> 8) & 0xff (for normal exit).
struct proc_exit_event {
    struct event_header h;
    char comm[TASK_COMM_LEN];
    int  exit_code;
};


// Event for execve syscall (ARES_EVENT_EXECVE).
// Emitted at sys_enter_execve; comm is the calling thread name before exec replaces it.
// argv[] entries beyond argc are zero-initialised.
// call_stack[0..stack_depth) is the user-space stack at execve entry.
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
//
// prop_info layout (Android 8+, bionic, stable across API 26-35):
//   offset  0: atomic_uint_least32_t serial   (4 bytes)
//   offset  4: char value[92]                 (PROP_VALUE_MAX)
//   offset 96: char name[0]                   (flexible array)
//
// is_ret / found usage by type:
//   PROP_READ  — is_ret=0, found=0  (entry of read_callback; name+value always present)
//   PROP_GET   — is_ret=0: CALL, name only; is_ret=1: RET, name+value (value="" if empty)
//   PROP_FIND  — is_ret=0: CALL, name only; is_ret=1: RET, found=1→name+value, found=0→name only
//   PROP_SCAN  — is_ret=0, found=0  (entry of foreach; name/value empty)
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