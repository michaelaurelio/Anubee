#ifndef __ARES_TRACER_H
#define __ARES_TRACER_H

#define TASK_COMM_LEN 32
#define MAX_STR_LEN 128
#define NUM_ARGS 8

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


// Event for native function calls
struct event {
    struct event_header h;
    int ppid;
    bool exit_event;
    char comm[TASK_COMM_LEN];
    unsigned long args[NUM_ARGS];
    __u8 is_str[NUM_ARGS];
    char strings[NUM_ARGS][MAX_STR_LEN];
    // FEATURE: Add BETTER arguments later
    // FEATURE: Add retval later
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