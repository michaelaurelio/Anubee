#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe//apex/com.android.runtime/lib64/bionic/libc.so:open")
int BPF_KPROBE(uprobe_open)
{
    bpf_printk("open() called.");
    return 0;
}