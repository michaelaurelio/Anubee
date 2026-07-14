// SPDX-License-Identifier: GPL-2.0
#ifndef PROBE_SPEC_LOADER_H
#define PROBE_SPEC_LOADER_H

#include "probe_resolve.h"

// Reads probe specs from `path`, one per line, into `out[0..cap)`, starting at
// whatever is already in `*count` (caller-owned cursor — lets multiple files/
// -e entries accumulate into one array) and incrementing `*count` for each
// successfully parsed line. A malformed line (parse_custom_probe_spec returns
// nonzero) ABORTS the whole file: an error naming `path` and the 1-based line
// number is printed, and the function returns -1 immediately (a typo in a
// shared spec file must never be silently dropped). Trims leading AND
// trailing whitespace ('\n', '\r', ' ', '\t') from each line before parsing
// — so an indented comment or spec line is recognized as such. Skips blank
// lines and lines whose first non-removed character is '#'. Stops appending
// once *count reaches cap, and if EOF has not been reached at that point,
// prints one warning to stderr naming `path` and the cap value.
//
// Returns 0 if the whole file was opened and every non-comment/blank line
// parsed successfully (even if 0 such lines were present).
// Returns -1 if the file could not be opened, or if any line failed to
// parse, after printing an error via `log` (or stderr if `log` is NULL)
// naming `path` and either strerror(errno) (open failure) or the line
// number (parse failure).
//
// `log` is a printf-style logger, same signature as parse_custom_probe_spec's
// `log` parameter (see probe_resolve.h) — pass it straight through to
// parse_custom_probe_spec for per-line parse errors too. If `log` is NULL, use
// fprintf(stderr, ...) directly instead of calling through a NULL pointer.
int load_probe_spec_file(const char *path, custom_probe_spec_t *out, int cap,
                         int *count, void (*log)(const char *fmt, ...));

#endif /* PROBE_SPEC_LOADER_H */
