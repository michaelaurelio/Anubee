/* sym_pid.h
 *
 * Pure selection of the pid whose address space a recorded frame belongs to.
 *
 * A forked child's frames are valid in its parent's address space until execve
 * replaces its image: the stack of an exec event predates the exec, so it is
 * resolved against the parent. Every other event is resolved against the
 * event's own pid, whose maps may still be alive or retained after exit; the
 * parent is a lazy fallback only for a pid that never held a snapshot. `aux`
 * carries the parent tgid (low 31 bits) and a bit for "this event is
 * execve/execveat" (bit 31); 0 means unknown, i.e. stay with the event's own
 * pid.
 *
 * Header-only and libc-free so BPF objects and host tests can share it: BPF
 * gets __u32 from vmlinux.h, host code includes <linux/types.h> first.
 */
#ifndef ANUBEE_SYM_PID_H
#define ANUBEE_SYM_PID_H

#define SYM_AUX_EXEC 0x80000000u

/* The parent lookup is useful only for exec events and for the single-threaded
 * phase of a process, where the thread id equals the thread group id. */
static inline int sym_aux_wanted(int is_exec, __u32 tgid, __u32 tid)
{
	return is_exec || tgid == tid;
}

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

/* The pid whose own address space explains an event's frames first. An exec
 * event's stack predates the exec, so it belongs to the parent; every other
 * event belongs to the event's own pid. */
static inline int sym_first_pid(int pid, __u32 aux)
{
	int ppid = sym_aux_ppid(aux);

	if (sym_aux_is_exec(aux) && ppid > 1 && ppid != pid)
		return ppid;
	return pid;
}

/* With an event-sourced model the event's own pid is always the address
 * space: an exec event is named against the lines valid at its sequence
 * number. Without a model, the legacy choice applies. */
static inline int sym_first_pid_m(int pid, __u32 aux, int modelled)
{
	return modelled ? pid : sym_first_pid(pid, aux);
}

/* The parent pid to fall back to when the event pid has no mapping for a
 * frame. 0 when there is none: an exec event already resolves against the
 * parent, and an unusable parent cannot describe the frames. */
static inline int sym_fallback_pid(int pid, __u32 aux)
{
	int ppid = sym_aux_ppid(aux);

	if (sym_aux_is_exec(aux))
		return 0;
	if (ppid > 1 && ppid != pid)
		return ppid;
	return 0;
}

/* The parent fallback is useful only when the event pid's maps are gone and it
 * never held a snapshot of its own. */
static inline int sym_fallback_wanted(int gone, unsigned long long n)
{
	return gone == 1 && n == 0;
}

/* A stack snapshot is unwound through the parent only when the stack predates
 * an exec. */
static inline int sym_snapshot_parent(__u32 aux)
{
	return sym_aux_is_exec(aux) && sym_aux_ppid(aux) > 1;
}

/* An empty maps read must be discarded when an earlier read produced a
 * snapshot: the process exited, but its last mappings still name the frames
 * recorded before it did. */
static inline int sym_maps_discard_read(unsigned long long old_n,
					unsigned long long new_n)
{
	return old_n > 0 && new_n == 0;
}

/* Remember the parent tgid per process. The parent of a live tgid does not
 * change, and a tgid's first event is a leader event that carries it, so
 * recording it here lets later events of the same tgid (non-leader threads,
 * whose probe skips the parent read) still fall back to the parent. Direct
 * mapped, one 64-bit word per slot; lock-free, a relaxed 8-byte load per event.
 * An entry is (pid << 32) | ppid; 0 means empty, so a torn pair is impossible. */
#define SYM_PPIDC_SLOTS 1024

struct sym_ppidc {
	unsigned long long s[SYM_PPIDC_SLOTS];
};

static inline __u32 sym_ppidc_resolve(struct sym_ppidc *c, int pid, __u32 aux)
{
	if (pid <= 0)
		return aux;

	unsigned int slot = (unsigned int)pid & (SYM_PPIDC_SLOTS - 1);

	if (sym_aux_ppid(aux) > 0) {
		unsigned long long entry =
			((unsigned long long)(unsigned int)pid << 32) |
			(unsigned int)sym_aux_ppid(aux);

		if (__atomic_load_n(&c->s[slot], __ATOMIC_RELAXED) != entry)
			__atomic_store_n(&c->s[slot], entry, __ATOMIC_RELAXED);
		return aux;
	}

	unsigned long long entry = __atomic_load_n(&c->s[slot], __ATOMIC_RELAXED);
	__u32 ppid = (__u32)entry;

	if (ppid > 0 && (__u32)(entry >> 32) == (unsigned int)pid)
		return sym_aux_make((int)ppid, 0);
	return aux;
}

#endif /* ANUBEE_SYM_PID_H */
