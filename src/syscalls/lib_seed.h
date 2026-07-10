#ifndef ARES_SYSCALLS_LIB_SEED_H
#define ARES_SYSCALLS_LIB_SEED_H

#include <string.h>
#include "common/maps.h"   // struct ares_map_line
#include "common/pattern_match.h"

// Pure decision predicate for seeding the lib-filter from an already-open
// /proc/<pid>/maps (lib-filter attribution defect, BACKLOG.md): libc.so et al.
// are mapped once in the zygote and inherited by the forked app via COW, so no
// uprobe_mmap ever fires for them in the child — the event-driven arming in
// syscalls.c never catches them, and the issuer check (attribution.h) silently
// misses every syscall they issue. A one-time maps scan at attach/launch time
// closes that gap; this predicate is the shared test also used live in
// syscalls.c's lib_name_matches(), so the two paths can't drift.
//
// Selector match on an already-extracted basename: substring, or glob (*?[])
// if `sel` contains glob metacharacters. Shared by lib_seed_line_arms() below
// and syscalls.c's live lib_name_matches(), so the two arming paths can't drift.
static inline int lib_selector_matches_name(const char *base, const char *sel)
{
    if (!sel[0])
        return 0;
    return pm_match(sel, base, false) ? 1 : 0;
}

// Returns 1 if `ml` is an executable, file-backed mapping whose basename
// matches selector `sel`. Header-only, no I/O, so it's host-testable without
// a maps file.
static inline int lib_seed_line_arms(const struct ares_map_line *ml, const char *sel)
{
    if (!ml->exec || ml->path[0] == '\0')
        return 0;

    const char *base = strrchr(ml->path, '/');
    base = base ? base + 1 : ml->path;

    return lib_selector_matches_name(base, sel);
}

#endif // ARES_SYSCALLS_LIB_SEED_H
