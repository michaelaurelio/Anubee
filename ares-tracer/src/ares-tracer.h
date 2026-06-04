#ifndef __ARES_TRACER_H
#define __ARES_TRACER_H

#define TASK_COMM_LEN	 32
#define MAX_FILENAME_LEN 256

struct event {
    int pid;
    int tid;
    int ppid;
    char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
    // FEATURE: Add arguments later
    // FEATURE: Add retval later
};

#endif /* __ARES_TRACER_H */