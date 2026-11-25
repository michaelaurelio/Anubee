/* hdr_aux.bpf.h
 *
 * BPF-side packer for trace_event_header._pad. Engines that symbolize frames in
 * userspace store the parent tgid (low 31 bits) plus bit 31 = "this syscall is
 * execve/execveat", so a forked child's frames can be resolved against the
 * parent's address space. 0 means unknown.
 *
 * Include after vmlinux.h and bpf_core_read.h: they provide task_struct,
 * bpf_get_current_task and BPF_CORE_READ.
 */
#ifndef ANUBEE_HDR_AUX_BPF_H
#define ANUBEE_HDR_AUX_BPF_H

#include "common/sym_pid.h"

static __always_inline __u32 anubee_hdr_aux(__u64 nr)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int ppid = BPF_CORE_READ(task, real_parent, tgid);
	return sym_aux_make(ppid, nr == 221 || nr == 281);  /* arm64 execve / execveat */
}

#endif /* ANUBEE_HDR_AUX_BPF_H */
