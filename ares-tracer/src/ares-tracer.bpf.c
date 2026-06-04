#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(uprobe_open)
{
    bpf_printk("BPF called.");
    return 0;
}