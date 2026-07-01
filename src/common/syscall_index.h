#ifndef ARES_SYSCALL_INDEX_H
#define ARES_SYSCALL_INDEX_H
#include <stddef.h>

// arm64 generic __NR max is ~463; 512 covers it with headroom. Any nr >= cap
// falls back to a cold linear scan (correctness preserved, no magic-number risk).
#define ARES_SYS_NR_CAP 512

struct ares_sysent { long nr; const char *name; };

struct ares_sysindex {
	const char               *by_nr[ARES_SYS_NR_CAP];  // hot path, nr < cap
	const struct ares_sysent *table;                   // cold fallback, nr >= cap
	size_t                    count;
};

// Build the nr index once from a {nr,name} table. Idempotent; call at setup
// before any worker/drain thread starts (so the fill is race-free).
static inline void ares_sysindex_build(struct ares_sysindex *ix,
                                       const struct ares_sysent *table,
                                       size_t count)
{
	for (size_t i = 0; i < ARES_SYS_NR_CAP; i++)
		ix->by_nr[i] = NULL;
	for (size_t i = 0; i < count; i++) {
		long nr = table[i].nr;
		if (nr >= 0 && nr < ARES_SYS_NR_CAP)
			ix->by_nr[nr] = table[i].name;
	}
	ix->table = table;
	ix->count = count;
}

// O(1) for common syscalls; cold linear fallback for nr >= cap. NULL if unknown.
static inline const char *ares_sysindex_name(const struct ares_sysindex *ix,
                                             long nr)
{
	if (nr >= 0 && nr < ARES_SYS_NR_CAP && ix->by_nr[nr])
		return ix->by_nr[nr];
	for (size_t i = 0; i < ix->count; i++)   // nr >= cap (never on arm64 today)
		if (ix->table[i].nr == nr)
			return ix->table[i].name;
	return NULL;
}

#endif // ARES_SYSCALL_INDEX_H
