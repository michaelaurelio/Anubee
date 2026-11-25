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

/* The parent lookup is useful only for exec events and for the single-threaded
 * phase of a process, where the thread id equals the thread group id. */
static inline int sym_aux_wanted(int is_exec, __u32 tgid, __u32 tid)
{
	return is_exec || tgid == tid;
}

/* Per-pid cache for "the child's maps are gone". Direct mapped, so a slot
 * collision replaces the previous entry. */
#define SYM_PIDC_SLOTS 64
#define SYM_PIDC_ALIVE_MS 250
#define SYM_PIDC_GONE_MS 5000

struct sym_pidc_slot {
	int pid;
	int gone;
	long long stamp_ms;
};

struct sym_pidc {
	struct sym_pidc_slot s[SYM_PIDC_SLOTS];
};

/* Return 1 and fill *gone on a live cache hit, 0 on a miss or expired entry.
 * Alive and gone entries use separate lifetimes. */
static inline int sym_pidc_get(struct sym_pidc *c, int pid, long long now_ms,
			       int *gone)
{
	if (pid <= 0)
		return 0;

	struct sym_pidc_slot *slot = &c->s[(unsigned int)pid & (SYM_PIDC_SLOTS - 1)];
	long long age;

	if (slot->pid != pid)
		return 0;
	age = now_ms - slot->stamp_ms;
	if (age < 0)
		return 0;
	if (age >= (slot->gone ? SYM_PIDC_GONE_MS : SYM_PIDC_ALIVE_MS))
		return 0;

	if (gone)
		*gone = slot->gone;
	return 1;
}

/* Store a pid decision with the current timestamp. */
static inline void sym_pidc_put(struct sym_pidc *c, int pid, int gone,
				long long now_ms)
{
	struct sym_pidc_slot *slot = &c->s[(unsigned int)pid & (SYM_PIDC_SLOTS - 1)];

	slot->pid = pid;
	slot->gone = gone ? 1 : 0;
	slot->stamp_ms = now_ms;
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
