// SPDX-License-Identifier: GPL-2.0
//
// ares trace — run the kprobe (syscalls), uprobe (funcs), and library-load (lib)
// engines together from a SINGLE app launch. This is a thin coordinator: it
// reuses each engine's setup/run/teardown phases unchanged, arms all requested
// engines before the one launch, then drains their ring buffers concurrently.
// It is inherently LOUD if --funcs is used — the uprobe engine writes a BRK
// into the target — so it never sits on the stealthy side of the detectability
// firewall in that case. See DOCUMENTATION.md / BACKLOG.md.
//
// trace composes only the homogeneous streaming engines (syscalls/funcs/lib) —
// one launch, one concurrent ring-drain, one merged JSONL stream. `correlate`
// (itself a funcs+syscalls fusion; needs a post-launch uprobe attach once the
// child PID is known, so it doesn't fit "arm everything before the single
// launch") and `dump` (a batch engine — rebuilt .so artifacts, not a JSONL
// stream) are standalone-only (`ares correlate` / `ares dump`); composing them
// here would double-instrument the same targets. See BACKLOG.md.
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

#include "common/launch.h"   // struct ares_run_ctx, ares_resolve_uid, ares_launch_app
#include "common/runtime.h"  // ares_install_stop_handler
#include "common/jsonl_merge.h"  // EPIC C5: combine each engine's own -o file into one
#include "trace/trace_args.h"

// Engine driver entry points (setup/run/teardown for syscalls/funcs/lib, plus
// correlate/dump for other callers of this header). Defined in their
// respective engines and kept global through the partial-link (see the
// --keep-global-symbol lists in the Makefile) — declared once in
// common/engine_driver.h so this coordinator and each engine's definition can't
// silently drift (AA3).
#include "common/engine_driver.h"

// One stop flag shared by all engines' poll loops; set by the shared SIGINT/SIGTERM
// stop handler (the engines do not install their own when driven here).
static volatile sig_atomic_t g_stop;

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s (-P <package> | -p <pid[,pid...]>) [-o <prefix>] "
		"[--syscalls <args...>] [--funcs <args...>] [--lib]\n"
		"\n"
		"Run the kprobe syscall tracer, uprobe function tracer, and/or library-load\n"
		"tracer together from a single app launch (LOUD: the uprobe writes a BRK into\n"
		"the target if --funcs is used).\n"
		"\n"
		"  -P <package>    app to launch and trace (mutually exclusive with -p)\n"
		"  -p <pid[,...]>  attach to already-running PID(s) instead of launching\n"
		"                  (mutually exclusive with -P; each engine arms its own\n"
		"                  target_pids from this list, no UID resolve/launch)\n"
		"  -A <activity>   override launch activity component (default: auto-resolve)\n"
		"  -o <prefix>     write <prefix>.syscalls.jsonl, <prefix>.funcs.jsonl, and/or\n"
		"                  <prefix>.lib.jsonl (recommended: keeps engine streams\n"
		"                  separate and silences console output)\n"
		"  --syscalls ...  options for the syscalls engine, e.g. '-a' or '<lib> -s openat'\n"
		"                  (no package/PID args — they come from -P/-p above)\n"
		"  --funcs ...     options for the funcs engine, e.g. \"-e 'libc.so!open' -J\"\n"
		"                  (no package/PID args — they come from -P/-p above)\n"
		"  --lib           enable library-load tracing (accepts shared -o/-v/-q/-J options)\n"
		"\n"
		"-P/-p, -A, and -o must come before the --syscalls / --funcs / --lib sections.\n"
		"\n"
		"correlate and dump are standalone-only (`ares correlate` / `ares dump`) — not\n"
		"composable into trace.\n",
		argv0);
}

struct run_arg { int (*run)(volatile sig_atomic_t *); };
static void *run_thread(void *p)
{
	struct run_arg *a = p;
	a->run(&g_stop);
	return NULL;
}

// One row per streaming engine trace composes. Adding/removing an engine from
// `trace` is a one-row change here instead of a copy-pasted block per phase
// (build/arm/launch/drain/teardown/merge) — see BACKLOG.md.
struct engine {
	const char *name;    // argv[0] for the synthetic argv, and trace_build_argv's "engine"
	const char *suffix;  // "<prefix>.<suffix>" output filename
	int  (*setup)(int argc, char **argv, const struct ares_run_ctx *rc);
	int  (*run)(volatile sig_atomic_t *stop);
	void (*teardown)(void);

	// Filled in by cmd_trace before use:
	int  start, end;        // [start,end) slice into argv; start<0 = not requested
	bool want;
	struct trace_argv v;
	int  argc;
	pthread_t th;
	bool th_ok;
};

static struct engine engines[] = {
	{ .name = "syscalls", .suffix = "syscalls.jsonl",
	  .setup = syscalls_setup, .run = syscalls_run, .teardown = syscalls_teardown },
	{ .name = "funcs",    .suffix = "funcs.jsonl",
	  .setup = funcs_setup,    .run = funcs_run,    .teardown = funcs_teardown },
	{ .name = "lib",      .suffix = "lib.jsonl",
	  .setup = lib_setup,      .run = lib_run,      .teardown = lib_teardown },
};
#define NUM_ENGINES (int)(sizeof(engines) / sizeof(engines[0]))

int cmd_trace(int argc, char **argv)
{
	struct trace_args ta;
	int pr = trace_parse_args(argc, argv, &ta);
	if (pr == 1) { usage(argv[0]); return 0; }   // -h/--help
	if (pr < 0)  { usage(argv[0]); return 1; }
	const char *pkg = ta.pkg, *prefix = ta.prefix, *activity = ta.activity;
	const char *pids = ta.pids;

	engines[0].start = ta.sys_start;  engines[0].end = ta.sys_end;
	engines[1].start = ta.func_start; engines[1].end = ta.func_end;
	engines[2].start = ta.lib_start;  engines[2].end = ta.lib_end;

	if (!pkg && !pids) {
		fprintf(stderr, "trace: one of -P <package> / -p <pid[,...]> is required\n");
		usage(argv[0]); return 1;
	}
	bool any_want = false;
	for (int k = 0; k < NUM_ENGINES; k++) {
		engines[k].want = (engines[k].start >= 0);
		any_want = any_want || engines[k].want;
	}
	if (!any_want) {
		fprintf(stderr, "trace: at least one of --syscalls / --funcs / --lib is required\n");
		usage(argv[0]); return 1;
	}
	if (!prefix)
		fprintf(stderr, "trace: no -o; the engines' console output will interleave "
		                "— use -o <prefix> for clean per-engine JSONL\n");

	int uid = 0;
	if (pkg) {
		uid = ares_resolve_uid(pkg);
		if (uid < 0) {
			fprintf(stderr, "trace: cannot resolve UID for '%s' (installed? run as root?)\n", pkg);
			return 1;
		}
	}
	// -p attach mode: rc stays zeroed — each engine reads "-p <pids>" from its own
	// argv (injected below) and arms target_pids itself, same as standalone.
	struct ares_run_ctx rc = { .uid = uid, .pkg = pkg };

	// Build each engine's argv: ["<engine>", ("-o" file)?, <section args...>].
	// All engines read the package name from rc->pkg (pre-filled before argp_parse).
	for (int k = 0; k < NUM_ENGINES; k++) {
		struct engine *e = &engines[k];
		if (!e->want) continue;
		int tr = 0;
		e->argc = trace_build_argv(&e->v, e->name, prefix, e->suffix, argv, e->start, e->end, &tr);
		if (tr) fprintf(stderr, "trace: --%s section truncated (too many args)\n", e->name);
		// -p attach mode: inject "-p <pids>" so the engine arms target_pids itself.
		if (pids && e->argc < TRACE_ARGV_CAP - 2) {
			e->v.argv[e->argc++] = "-p";
			e->v.argv[e->argc++] = (char *)pids;
			e->v.argv[e->argc]   = NULL;
		} else if (pids) {
			fprintf(stderr, "trace: --%s section full; -p not injected (target unset)\n", e->name);
		}
		// SYM1 Phase 1: -o no longer implies -q inside the engine, so trace must
		// inject -q itself under -o (else its concurrent engines' stdout
		// interleaves unusably, per the warning above when -o is absent).
		if (prefix && e->argc < TRACE_ARGV_CAP - 1) {
			e->v.argv[e->argc++] = "-q";
			e->v.argv[e->argc]   = NULL;
		} else if (prefix) {
			fprintf(stderr, "trace: --%s section full; -q not injected\n", e->name);
		}
	}

	// Arm all requested engines BEFORE the single launch. None launch on their
	// own — setup only opens/loads/attaches and installs the UID filter (via rc->uid).
	for (int k = 0; k < NUM_ENGINES; k++) {
		struct engine *e = &engines[k];
		if (!e->want) continue;
		if (e->setup(e->argc, e->v.argv, &rc) != 0) {
			fprintf(stderr, "trace: %s setup failed\n", e->name);
			for (int j = k - 1; j >= 0; j--)
				if (engines[j].want) engines[j].teardown();
			return 1;
		}
	}

	ares_install_stop_handler(&g_stop);

	if (pids) {
		// -p attach mode: engines already armed target_pids in setup above; there
		// is no launch (the target is already running).
		printf("trace: attaching to pid(s) %s\n", pids);
	} else {
		ares_launch_banner(pkg, uid);
		pid_t pid;
		if (ares_launch_app(pkg, activity, &pid) != 0) {
			fprintf(stderr, "trace: launch failed for '%s'\n", pkg);
			for (int j = NUM_ENGINES - 1; j >= 0; j--)
				if (engines[j].want) engines[j].teardown();
			return 1;
		}
		(void)pid;  // no engine composed by trace needs the launched pid post-hoc
	}

	// Drain all ring buffers concurrently until Ctrl-C. Each engine has its own
	// ring buffer, but src/common/symbolize.c's caches are shared (single linked
	// copy, not symbol-localized) — sym_resolve/sym_flush_pid/cfi_unwind_snapshot
	// all serialize on symbolize.c's internal g_lock (AA1 fix, 2026-07-07), so the
	// engines' threads don't race on those globals despite calling into them
	// concurrently. The only state owned directly by this file is g_stop.
	struct run_arg run_args[NUM_ENGINES];
	for (int k = 0; k < NUM_ENGINES; k++) {
		struct engine *e = &engines[k];
		if (!e->want) continue;
		run_args[k].run = e->run;
		e->th_ok = (pthread_create(&e->th, NULL, run_thread, &run_args[k]) == 0);
	}
	// Fallback: if a thread failed to spawn, drain that engine inline.
	for (int k = 0; k < NUM_ENGINES; k++) {
		struct engine *e = &engines[k];
		if (e->want && !e->th_ok) e->run(&g_stop);
	}
	for (int k = 0; k < NUM_ENGINES; k++) {
		struct engine *e = &engines[k];
		if (e->want && e->th_ok) pthread_join(e->th, NULL);
	}

	for (int k = NUM_ENGINES - 1; k >= 0; k--)
		if (engines[k].want) engines[k].teardown();

	// EPIC C5: each engine above wrote its own <prefix>.<suffix>.jsonl (per-engine
	// files kept, unchanged - purely additive). Also merge them into one file at
	// the literal -o value, so a caller expecting a single combined stream (e.g.
	// ARES-Desktop's Capture UI, which already re-sorts every record by the
	// shared `ktime` field rather than by file position - EPIC C3/C4, so a
	// concatenation, not a true byte-interleave, is all correctness requires)
	// gets exactly that without knowing about the per-engine suffixes.
	if (prefix) {
		const char *srcs[NUM_ENGINES];
		int n = 0;
		char paths[NUM_ENGINES][600];
		for (int k = 0; k < NUM_ENGINES; k++) {
			if (!engines[k].want) continue;
			snprintf(paths[k], sizeof(paths[k]), "%s.%s", prefix, engines[k].suffix);
			srcs[n++] = paths[k];
		}
		int merged = jsonl_merge(prefix, srcs, n);
		if (merged >= 0)
			fprintf(stderr, "trace: merged %d file(s) into %s\n", merged, prefix);
	}
	return 0;
}
