#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ares-tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");


// Determine if a value is a user-space pointer (heuristic) -> CHANGE LATER
static __always_inline bool is_user_ptr(unsigned long val)
{
    unsigned long untagged = val & 0x00FFFFFFFFFFFFFFUL;
    return untagged > 0x10000UL && untagged < 0x800000000000UL;
}


// 
SEC("uprobe")
int BPF_KPROBE(uprobe_open, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
    // Initializations stuff
    struct task_struct *task;
    struct event *e;
    pid_t pid;
    pid_t tid;

    pid = bpf_get_current_pid_tgid() >> 32;
    tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;


    // Reserve space in ring buffer for event
    e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e)
        return 0;


    // Fill event data
    task = (struct task_struct *)bpf_get_current_task();

    e->pid = pid;
    e->tid = tid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->exit_event = false;

    // TEMP STUFF, FIX TOMORROW
    long raw[NUM_ARGS] = {a1, a2, a3, a4, a5, a6, a7, a8};
    #pragma unroll
    for (int i = 0; i < NUM_ARGS; i++) {
        e->args[i] = (unsigned long)raw[i];
        e->is_str[i] = 0;
        if (is_user_ptr((unsigned long)raw[i])) {
            long n = bpf_probe_read_user_str(e->strings[i], MAX_STR_LEN, (void*)raw[i]);
            if (n > 1)
                e->is_str[i] = 1;
        }
    }

    // TEMP STUFF, FIX TOMORROW
    // e->args[0] = a1;
    // e->args[1] = a2;
    // e->args[2] = a3;
    // e->args[3] = a4;
    // e->args[4] = a5;
    // e->args[5] = a6;
    // e->args[6] = a7;
    // e->args[7] = a8;

    bpf_ringbuf_submit(e, 0);
    return 0;
}