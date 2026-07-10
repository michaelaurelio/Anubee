// SPDX-License-Identifier: GPL-2.0
#ifndef __ARES_COMMON_PATTERN_MATCH_H
#define __ARES_COMMON_PATTERN_MATCH_H

#include <stdbool.h>

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

#endif /* __ARES_COMMON_PATTERN_MATCH_H */
