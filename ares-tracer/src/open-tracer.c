#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "open-tracer.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main()
{
    struct open_tracer_bpf *skel;
    int err;
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    skel = open_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = open_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Tracing open() | cat /sys/kernel/debug/tracing/trace_pipe\n");

    for (;;) {
        if (exiting) 
            goto cleanup;
        pause();
    }

    cleanup:
        open_tracer_bpf__destroy(skel);
        return -err;
}