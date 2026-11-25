/* sym_pid.h
 *
 * Pure selection of the pid whose address space a recorded frame belongs to.
 *
 * A forked child's frames are valid in its parent's address space: the child is
 * a copy of it until execve replaces it. The child's own /proc/<pid>/maps are
 * gone after it exits and describe the new image after execve, so symbolizing
 * against the parent recovers the frame names. `aux` carries the parent tgid
 * (low 31 bits) and a bit for "this event is execve/execveat" (bit 31); 0 means
 * unknown, i.e. stay with the event's own pid.
 *
 * Header-only and libc-free so BPF objects and host tests can share it: BPF
 * gets __u32 from vmlinux.h, host code includes <linux/types.h> first.
 */
#ifndef ANUBEE_SYM_PID_H
#define ANUBEE_SYM_PID_H

#define SYM_AUX_EXEC 0x80000000u

/* Pack a parent tgid and the exec flag. An unusable ppid means "unknown", so
 * the flag is dropped too. */
static inline __u32 sym_aux_make(int ppid, int is_exec)
{
	if (ppid <= 0)
		return 0;
	return ((__u32)ppid & 0x7fffffffu) | (is_exec ? SYM_AUX_EXEC : 0);
}

static inline int sym_aux_ppid(__u32 aux)
{
	return (int)(aux & 0x7fffffffu);
}

static inline int sym_aux_is_exec(__u32 aux)
{
	return (aux & SYM_AUX_EXEC) != 0;
}

/* The parent explains the frames only when it is a real process other than the
 * event pid, and either the stack predates an execve or the child's own maps
 * are gone. Otherwise the event's pid is the right address space. */
static inline int sym_pick_pid(int pid, __u32 aux, int child_maps_gone)
{
	int ppid = sym_aux_ppid(aux);

	if (ppid > 1 && ppid != pid && (sym_aux_is_exec(aux) || child_maps_gone))
		return ppid;
	return pid;
}

#endif /* ANUBEE_SYM_PID_H */
