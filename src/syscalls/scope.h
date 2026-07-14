#ifndef ARES_SYSCALLS_SCOPE_H
#define ARES_SYSCALLS_SCOPE_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// syscall:LIBPATTERN!NAME per-syscall library scoping. Pure parsing/validation
// helpers only (no BPF/state), kept header-only so they're host-testable the
// same way lib_seed.h's predicates are -- syscalls.c itself needs the
// generated BPF skeleton to compile at all, so logic worth unit testing lives
// here instead.

// Splits an already-deny-stripped SPEC_KIND_SYSCALL spec's `mod` string (see
// probe_resolve.c's SPEC_KIND_SYSCALL branch, which already consumes a
// leading '!' as the deny marker before mod is set) on the first remaining
// '!' -- the same first-'!' rule probe_resolve.c uses for MODULE!FUNC, so
// "libc.so!openat" and "/lib.*/!openat" (regex library pattern) both split
// the same way a funcs: target would.
//
// Returns: 1 = scoped, libpat/name filled in; 0 = unscoped (no '!' in mod;
// name/libpat left untouched); -1 = malformed ('!' present but libpat or
// name is empty, e.g. "libc.so!" or "!openat", or either half doesn't fit
// the output buffer).
static inline int sysc_scope_split(const char *mod, char *libpat, size_t libpat_sz,
                                    char *name, size_t name_sz)
{
	const char *bang = strchr(mod, '!');
	if (!bang)
		return 0;
	size_t lp_len = (size_t)(bang - mod);
	const char *nm = bang + 1;
	if (lp_len == 0 || lp_len >= libpat_sz || nm[0] == '\0' || strlen(nm) >= name_sz)
		return -1;
	memcpy(libpat, mod, lp_len);
	libpat[lp_len] = '\0';
	snprintf(name, name_sz, "%s", nm);
	return 1;
}

// Does comma-separated `list` (the -s/-x LIST value) contain `name` as one of
// its entries? Mirrors install_syscall_filter's own tokenization (syscalls.c)
// exactly, so the two can never drift on what counts as a listed name
// (leading spaces per entry skipped, same as there).
static inline bool sysc_list_contains(const char *list, const char *name)
{
	if (!list)
		return false;
	char buf[1024];
	snprintf(buf, sizeof(buf), "%s", list);
	char *save = NULL;
	for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ')
			tok++;
		if (!strcmp(tok, name))
			return true;
	}
	return false;
}

#endif // ARES_SYSCALLS_SCOPE_H
