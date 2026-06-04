#ifndef __ARES_TRACER_H
#define __ARES_TRACER_H

#define TASK_COMM_LEN 32
#define MAX_STR_LEN 128
#define NUM_ARGS 8

struct event {
    int pid;
    int tid;
    int ppid;
    bool exit_event;
    char comm[TASK_COMM_LEN];
    unsigned long args[NUM_ARGS];
    __u8 is_str[NUM_ARGS];
    char strings[NUM_ARGS][MAX_STR_LEN];
    // FEATURE: Add BETTER arguments later
    // FEATURE: Add retval later
};

#endif /* __ARES_TRACER_H */