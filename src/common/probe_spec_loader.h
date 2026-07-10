// SPDX-License-Identifier: GPL-2.0
#ifndef PROBE_SPEC_LOADER_H
#define PROBE_SPEC_LOADER_H

#include "probe_resolve.h"

// Reads probe specs from `path`, one per line, into `out[0..cap)`, starting at
// whatever is already in `*count` (caller-owned cursor — lets multiple files/
// -e entries accumulate into one array) and incrementing `*count` for each
// successfully parsed line. Malformed lines are skipped (parse_custom_probe_spec
// returns nonzero) — a bad line does not abort the whole file, matching existing
// funcs.c/correlate.c behavior. Trims trailing '\n', '\r', ' ', '\t' from each
// line before parsing. Skips blank lines and lines whose first non-removed
// character is '#'. Stops appending once *count reaches cap, and if EOF has not
// been reached at that point, prints one warning to stderr naming `path` and the
// cap value (match the style of the existing warnings you find in funcs.c/correlate.c
// for their own cap-reached cases — same tone, same stream).
//
// Returns 0 if the file was opened and read (even if 0 lines parsed).
// Returns -1 if the file could not be opened, after printing an error via `log`
// (or stderr if `log` is NULL) naming `path` and strerror(errno).
//
// `log` is a printf-style logger, same signature as parse_custom_probe_spec's
// `log` parameter (see probe_resolve.h) — pass it straight through to
// parse_custom_probe_spec for per-line parse errors too. If `log` is NULL, use
// fprintf(stderr, ...) directly instead of calling through a NULL pointer.
int load_probe_spec_file(const char *path, custom_probe_spec_t *out, int cap,
                         int *count, void (*log)(const char *fmt, ...));

#endif /* PROBE_SPEC_LOADER_H */
