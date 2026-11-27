// SPDX-License-Identifier: GPL-2.0
// Validation helpers for target-selection and probe-selector arguments at ARGP_KEY_END.
#ifndef TARGET_VALIDATE_H
#define TARGET_VALIDATE_H

#include <argp.h>
#include <errno.h>

// Enforces "exactly one of -p PID-list or -P PACKAGE" at ARGP_KEY_END.
// `n` = number of PIDs given via -p (i.e. args->tgt.n). `pkg` = the package
// string given via -P, or NULL/empty if not given. On violation prints via
// argp_error and returns EINVAL (0 when valid); the caller must return that
// from its parser, since ARGP_NO_EXIT makes argp_error itself return. Wording:
//   "specify exactly one of -p or -P"
// for both the "neither given" and "both given" cases.
error_t validate_pid_or_package(struct argp_state *state, int n, const char *pkg);

// Enforces "at least one probe selector was given" at ARGP_KEY_END, for
// engines that require some -e/-F/-I/-i selection (funcs, correlate).
// `nsel` = total count of selectors given (caller sums whatever counters it
// has — specs + regex patterns, etc). `hint` = a short string naming the
// flags this engine accepts, spliced into the error message as:
//   "no probe targets given (%s)"
// e.g. hint = "-e SPEC, -F FILE, or -I/-i regex". Prints via argp_error
// and returns EINVAL if nsel == 0, else 0 (caller returns it).
error_t validate_have_selector(struct argp_state *state, int nsel, const char *hint);

#endif
