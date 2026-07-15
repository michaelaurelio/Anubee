// SPDX-License-Identifier: GPL-2.0
// Pure arg-section splitter for `ares trace` (no libbpf/pthread deps) so it is
// host-testable — see tests/test_trace_args.c.
#ifndef ARES_TRACE_ARGS_H
#define ARES_TRACE_ARGS_H

struct trace_args {
	const char *pkg;       // -P value, or NULL (launch mode; mutually exclusive with pids)
	const char *prefix;    // -o value, or NULL
	const char *activity;  // -A value, or NULL
	const char *pids;      // -p value (raw PID[,PID...] csv), or NULL (attach mode)
	int sys_start, sys_end;    // [start,end) slice into argv; start<0 = no --syscalls
	int func_start, func_end;  // likewise for --funcs
	int lib_start, lib_end;    // likewise for --lib
};

// Parse the coordinator-level flags and locate each engine section.
// argv[0] is the subcommand name. Returns 0 on success, 1 if -h/--help was seen
// (caller prints usage, exits 0), -1 on a flag missing its value or an
// unexpected token. A repeated section delimiter: the last one wins.
// `trace` composes only syscalls/funcs/lib (streaming engines); dump/correlate
// are standalone-only (see BACKLOG.md, dump/correlate removal from trace).
int trace_parse_args(int argc, char **argv, struct trace_args *out);

// Shared capacity for one engine's argv vector (NULL-terminated, so at most
// TRACE_ARGV_CAP-1 real entries). Named so trace.c's post-build injections
// (-p / -q) can bound themselves against the same limit trace_build_argv
// uses, instead of duplicating the literal in six places.
#define TRACE_ARGV_CAP 64

// Per-engine argv builder: owns storage for one NULL-terminated argv vector.
struct trace_argv {
	char *argv[TRACE_ARGV_CAP]; // NULL-terminated; [0] = engine name
	char  outbuf[512];          // backing store for the "-o <prefix>.<suffix>" argument
};

// Build one engine's argv into *out:
//   [ engine, ("-o" prefix.suffix)?, src_argv[start..end) ]
// prefix != NULL: insert "-o" "<prefix>.<suffix>" before the section args.
// If the section overflows TRACE_ARGV_CAP-1 slots the remainder is dropped and
// *truncated is set to 1 (caller warns). Returns argc (not counting NULL).
int trace_build_argv(struct trace_argv *out, const char *engine,
                     const char *prefix, const char *suffix,
                     char **src_argv, int start, int end,
                     int *truncated);

#endif
