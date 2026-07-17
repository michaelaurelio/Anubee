#ifndef ANUBEE_SYSCALL_INDEX_H
#define ANUBEE_SYSCALL_INDEX_H
#include <stddef.h>

// arm64 generic __NR max is ~463; 512 covers it with headroom. Any nr >= cap
// falls back to a cold linear scan (correctness preserved, no magic-number risk).
#define ANUBEE_SYS_NR_CAP 512

struct anubee_sysent { long nr; const char *name; };

struct anubee_sysindex {
	const char               *by_nr[ANUBEE_SYS_NR_CAP];  // hot path, nr < cap
	const struct anubee_sysent *table;                   // cold fallback, nr >= cap
	size_t                    count;
};

// Build the nr index once from a {nr,name} table. Idempotent; call at setup
// before any worker/drain thread starts (so the fill is race-free).
static inline void anubee_sysindex_build(struct anubee_sysindex *ix,
                                       const struct anubee_sysent *table,
                                       size_t count)
{
	for (size_t i = 0; i < ANUBEE_SYS_NR_CAP; i++)
		ix->by_nr[i] = NULL;
	for (size_t i = 0; i < count; i++) {
		long nr = table[i].nr;
		if (nr >= 0 && nr < ANUBEE_SYS_NR_CAP)
			ix->by_nr[nr] = table[i].name;
	}
	ix->table = table;
	ix->count = count;
}

// O(1) for common syscalls; cold linear fallback for nr >= cap. NULL if unknown.
static inline const char *anubee_sysindex_name(const struct anubee_sysindex *ix,
                                             long nr)
{
	if (nr >= 0 && nr < ANUBEE_SYS_NR_CAP && ix->by_nr[nr])
		return ix->by_nr[nr];
	for (size_t i = 0; i < ix->count; i++)   // nr >= cap (never on arm64 today)
		if (ix->table[i].nr == nr)
			return ix->table[i].name;
	return NULL;
}

#endif // ANUBEE_SYSCALL_INDEX_H
