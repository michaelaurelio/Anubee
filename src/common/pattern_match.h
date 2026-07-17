// SPDX-License-Identifier: GPL-2.0
#ifndef __ANUBEE_COMMON_PATTERN_MATCH_H
#define __ANUBEE_COMMON_PATTERN_MATCH_H

#include <stdbool.h>
#include <stddef.h>

// One shared matching primitive for the probe-spec selectors (funcs/correlate
// module & syscall/lib patterns, dump PATTERN, mod NAME), retiring the
// independently-reimplemented glob checks in lib_seed.h / rebuild.c /
// probe_resolve.c that previously used inconsistent trigger chars.

// Glob trigger chars standardized to "*?[" everywhere (fnmatch semantics).
bool pm_is_glob(const char *pattern);

// True if pattern is '/'-delimited regex syntax, e.g. "/^encrypt/".
bool pm_is_regex(const char *pattern);

// Literal/glob match of one text against pattern. exact=true -> strcmp
// fallback (whole-string match); exact=false -> strstr (substring match).
bool pm_match(const char *pattern, const char *text, bool exact);

// POSIX extended-regex match. Strips '/'...'/' delimiters if present, else
// treats pattern as a bare regex. Compiles+execs+frees each call (this is
// mapping-scan frequency, not a hot per-event path).
bool pm_regex(const char *pattern, const char *text);

// Parse-time syntax check for a (possibly '/'...'/' delimited) regex pattern,
// so a malformed regex is rejected when the spec is parsed instead of just
// silently never matching later inside pm_regex. On failure, `err` (if
// non-NULL) is filled with regcomp's error string. Same delimiter-stripping
// as pm_regex.
bool pm_regex_valid(const char *pattern, char *err, size_t errlen);

#endif /* __ANUBEE_COMMON_PATTERN_MATCH_H */
