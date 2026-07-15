// SPDX-License-Identifier: GPL-2.0
// Pure validation of dump's selector/trigger combination (no libbpf/libelf
// deps) so it is host-testable - dump.c itself includes dump.skel.h and cannot
// link host-side. Same split as src/trace/trace_args.{c,h}.
#ifndef ARES_DUMP_ARGS_H
#define ARES_DUMP_ARGS_H

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
//   - --check requires --now: only the --now path consults it, so allowing
//     --check on the dump-on-exit path would silently write .so files instead
//     of comparing - the wrong artifact, with no error
const char *dump_args_check(const struct dump_trigger *t);

#endif /* ARES_DUMP_ARGS_H */
