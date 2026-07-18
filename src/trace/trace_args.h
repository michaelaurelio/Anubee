// SPDX-License-Identifier: GPL-2.0
// Pure flat flag router for `anubee trace` (no libbpf/pthread/libelf deps) so it
// is host-testable — see tests/test_trace_args.c. Markers (--syscalls/--funcs/
// --lib sections) are gone: every flag is recognized by its own letter/name and
// routed to whichever engine(s) understand it; presence of an engine-unique
// flag (or a KIND-routed -e/-F spec, classified by trace.c where the ELF-aware
// spec parser lives) enables that engine.
#ifndef ANUBEE_TRACE_ARGS_H
#define ANUBEE_TRACE_ARGS_H

#include <stdbool.h>
#include <stdio.h>

// Shared capacity for one engine's argv vector (NULL-terminated, so at most
// TRACE_ARGV_CAP-1 real entries). Named so trace.c's post-build injections
// (-p / -q) can bound themselves against the same limit trace_build_argv
// uses, instead of duplicating the literal in six places. Also used as the
// cap for trace_args's own per-engine token accumulators and collected specs
// below, so one constant bounds every array this file owns.
#define TRACE_ARGV_CAP 64

// One collected top-level -e/-F occurrence. `val` points into the original
// argv (not copied). Classification (which KIND -> which engine) happens in
// trace.c, where the ELF-aware probe-spec parser lives — this file stays
// dependency-free.
struct trace_spec {
	char *val;      // the SPEC (for -e) or FILE (for -F) argument
	bool  is_file;  // true = came from -F, false = came from -e
};

struct trace_args {
	const char *pkg;       // -P value, or NULL (launch mode; mutually exclusive with pids)
	const char *prefix;    // -o value, or NULL
	const char *activity;  // -A value, or NULL
	const char *pids;      // -p value (raw PID[,PID...] csv), or NULL (attach mode)

	// Per-engine raw token accumulators: flags this engine's own argp will
	// re-parse verbatim (broadcast common flags like -v/-q, plus each
	// engine's unique flags like --syscalls/-s/-x/-l for syscalls or -S/-c for
	// funcs). Presence of an engine-unique flag also sets that engine's
	// want_* below; broadcast common flags do not change want_* on their own.
	char *sys_toks[TRACE_ARGV_CAP];  int sys_ntok;
	char *func_toks[TRACE_ARGV_CAP]; int func_ntok;
	char *lib_toks[TRACE_ARGV_CAP];  int lib_ntok;

	bool want_sys, want_func, want_lib;  // want_lib is set only by the bare --lib toggle

	int siblings, no_follow;  // deferred: forwarded to engines only in -p mode (else warn once)

	// Top-level -e/-F occurrences, collected but not yet classified (see
	// struct trace_spec above).
	struct trace_spec specs[TRACE_ARGV_CAP]; int nspec;
};

// Bounds-checked append into one of the per-engine token accumulators above.
// Shared by trace_parse_args (broadcast/unique-flag routing) and trace.c
// (appending a classified "-e"/"-F" spec token to its target engine) so the
// TRACE_ARGV_CAP bound is enforced in exactly one place. Returns false (and
// prints a warning naming `engine`) if the accumulator is full; the token is
// then dropped rather than overflowing trace_build_argv's own argv.
static inline bool trace_tok_push(char **toks, int *ntok, const char *engine, char *tok)
{
	if (*ntok >= TRACE_ARGV_CAP - 1) {
		fprintf(stderr, "trace: %s argument list full; '%s' dropped\n", engine, tok);
		return false;
	}
	toks[(*ntok)++] = tok;
	return true;
}

// Parse every `anubee trace` flag in one flat pass. argv[0] is the subcommand
// name. Returns 0 on success, 1 if -h/--help was seen (caller prints usage,
// exits 0), -1 on a flag missing its required value or an unrecognized token.
// Does not itself decide `want_sys`/`want_func` from -e/-F (that needs the
// KIND classifier in trace.c); the caller must OR those in after classifying
// trace_args::specs.
int trace_parse_args(int argc, char **argv, struct trace_args *out);

// Per-engine argv builder: owns storage for one NULL-terminated argv vector.
struct trace_argv {
	char *argv[TRACE_ARGV_CAP]; // NULL-terminated; [0] = engine name
	char  outbuf[512];          // backing store for the "-o <prefix>.<suffix>" argument
};

// Build one engine's argv into *out:
//   [ engine, ("-o" prefix.suffix)?, toks[0..ntok) ]
// prefix != NULL: insert "-o" "<prefix>.<suffix>" before the tokens.
// If the tokens overflow TRACE_ARGV_CAP-1 slots the remainder is dropped and
// *truncated is set to 1 (caller warns). Returns argc (not counting NULL).
int trace_build_argv(struct trace_argv *out, const char *engine,
                     const char *prefix, const char *suffix,
                     char **toks, int ntok, int *truncated);

#endif
