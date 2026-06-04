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

SEC("uprobe")
int BPF_KPROBE(uprobe_open)
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

    bpf_ringbuf_submit(e, 0);
    return 0;
}