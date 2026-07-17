// SPDX-License-Identifier: GPL-2.0
// Pure validation of dump's selector/trigger combination (no libbpf/libelf
// deps) so it is host-testable - dump.c itself includes dump.skel.h and cannot
// link host-side. Same split as src/trace/trace_args.{c,h}.
#ifndef ANUBEE_DUMP_ARGS_H
#define ANUBEE_DUMP_ARGS_H

// One parsed dump invocation, reduced to just what the rules need.
struct dump_trigger {
	int now;      // --now  (snapshot the -p targets immediately, no BPF)
	int check;    // --check (compare memory vs disk instead of writing .so)
	int on_map;   // --on-map
	int has_pkg;  // -P given
	int ntgt;     // number of -p PIDs
	int npat;     // number of -l / positional / spec-file lib: patterns
	int nbase;    // number of --base addresses
};

// Returns NULL when the combination is valid, else a static message suitable
// for argp_error(). Rules, in reporting order:
//   - exactly one of -p / -P
//   - at least one selector (-l pattern or --base)
//   - --now requires -p (-P launches an app; there is nothing to snapshot yet)
//   - --now and --on-map are mutually exclusive triggers
//   - --base requires --now: only the --now path threads the parsed bases
//     into the dump selector, so allowing --base on the dump-on-exit or
//     on-map paths would match nothing and hang waiting for a map event
//     that never comes - the same silent-failure class --now was built to
//     eliminate
//   - --check requires --now: only the --now path consults it, so allowing
//     --check on the dump-on-exit path would silently write .so files instead
//     of comparing - the wrong artifact, with no error
const char *dump_args_check(const struct dump_trigger *t);

/* Parse a --base ADDR argument (hex with 0x, or decimal; strtoull base 0).
 * Returns 0 and stores the value in *out on success, -1 on any rejection.
 *
 * The sign is rejected BEFORE parsing, not after: strtoull silently WRAPS a
 * negative, so "-1" yields ULLONG_MAX with end at the NUL and errno unset -
 * passing every after-the-fact check and quietly selecting 0xFFFFFFFFFFFFFFFF.
 * A load base is never negative, never signed, and never leading-whitespace,
 * so require it to start with a digit. */
int dump_parse_base(const char *arg, unsigned long long *out);

#endif /* ANUBEE_DUMP_ARGS_H */
