// SPDX-License-Identifier: GPL-2.0
//
// anubee trace — run the kprobe (syscalls), uprobe (funcs), and library-load (lib)
// engines together from a SINGLE app launch. This is a thin coordinator: it
// reuses each engine's setup/run/teardown phases unchanged, arms all requested
// engines before the one launch, then drains their ring buffers concurrently.
// It is inherently LOUD if funcs is enabled — the uprobe engine writes a BRK
// into the target — so it never sits on the stealthy side of the detectability
// firewall in that case. See DOCUMENTATION.md / BACKLOG.md.
//
// trace composes only the homogeneous streaming engines (syscalls/funcs/lib) —
// one launch, one concurrent ring-drain, one merged JSONL stream. `correlate`
// (itself a funcs+syscalls fusion; needs a post-launch uprobe attach once the
// child PID is known, so it doesn't fit "arm everything before the single
// launch") and `dump` (a batch engine — rebuilt .so artifacts, not a JSONL
// stream) are standalone-only (`anubee correlate` / `anubee dump`); composing them
// here would double-instrument the same targets. See BACKLOG.md.
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

#include "common/launch.h"   // struct anubee_run_ctx, anubee_resolve_uid, anubee_launch_app
#include "common/runtime.h"  // anubee_install_stop_handler
#include "common/jsonl_merge.h"  // EPIC C5: combine each engine's own -o file into one
#include "common/probe_resolve.h"      // custom_probe_spec_t, spec_kind_t, parse_custom_probe_spec
#include "common/probe_spec_loader.h"  // load_probe_spec_file
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
		"usage: %s (-P <package> | -p <pid[,pid...]>) [-o <prefix>] [-A <activity>]\n"
		"       [-v] [-q] [-b MB] [-Q MB] [--siblings] [--no-follow-fork]\n"
		"       [-e SPEC]... [-F FILE]... [-l PATTERN]...\n"
		"       [-a] [-s LIST] [-x LIST] [-S] [-c] [--snapshot | --no-snapshot] [--lib]\n"
		"\n"
		"Run the kprobe syscall tracer, uprobe function tracer, and/or library-load\n"
		"tracer together from a single app launch (LOUD: the uprobe writes a BRK into\n"
		"the target if funcs is enabled). No markers — each flag routes itself to the\n"
		"engine(s) that understand it, and its presence enables that engine:\n"
		"\n"
		"  -P <package>    app to launch and trace (mutually exclusive with -p)\n"
		"  -p <pid[,...]>  attach to already-running PID(s) instead of launching\n"
		"  -A <activity>   override launch activity component (default: auto-resolve)\n"
		"  -o <prefix>     write <prefix>.syscalls.jsonl, <prefix>.funcs.jsonl, and/or\n"
		"                  <prefix>.lib.jsonl (recommended: keeps engine streams\n"
		"                  separate and silences console output)\n"
		"  -v / -q         verbose / quiet (broadcast to every enabled engine)\n"
		"  --siblings, --no-follow-fork\n"
		"                  attach-mode target widening (broadcast; see -p)\n"
		"  -b MB / -Q MB   ring/queue buffer sizes (syscalls + funcs only; lib has none)\n"
		"  -e SPEC / -F FILE\n"
		"                  probe spec (repeatable); routed by KIND: prefix —\n"
		"                  syscall:NAME / lib:PATTERN -> syscalls, funcs:MODULE!FUNC or\n"
		"                  unprefixed (the default) -> funcs. A -F file may carry both\n"
		"                  kinds and enable both engines. mod: is not a trace engine.\n"
		"  -l PATTERN      syscalls library selector, equivalent to -e 'lib:PATTERN'\n"
		"  -a / -s LIST / -x LIST\n"
		"                  syscalls-only: capture all / allowlist / denylist; each enables syscalls\n"
		"  -S / -c         funcs-only: resolve-syms mode / caller-only; each enables funcs\n"
		"  --snapshot, --no-snapshot\n"
		"                  stack snapshots (broadcast to whichever of syscalls/funcs is enabled)\n"
		"  --lib           enable library-load tracing (no spec of its own)\n"
		"\n"
		"At least one engine must end up enabled (via a unique flag, a routed spec, or --lib).\n"
		"\n"
		"correlate and dump are standalone-only (`anubee correlate` / `anubee dump`) — not\n"
		"composable into trace.\n",
		argv0);
}

// Classify one collected top-level -e/-F spec by its KIND: prefix and route it
// to the engine(s) that read that kind, appending the original "-e"/"-F" + val
// tokens VERBATIM to that engine's accumulator (never rewritten — each engine's
// own argp re-parses exactly what it would have received in the old section
// form, so its output is byte-for-byte identical to before). Sets *want_sys /
// *want_func as appropriate. Returns 0 on success, -1 on a hard error (parse
// failure, or an explicit "-e mod:..." naming an engine trace doesn't compose).
static int classify_spec(struct trace_args *ta, const struct trace_spec *spec,
                         bool *want_sys, bool *want_func)
{
	const char *flag = spec->is_file ? "-F" : "-e";

	if (spec->is_file) {
		custom_probe_spec_t tmp[TRACE_ARGV_CAP];
		int n = 0;
		if (load_probe_spec_file(spec->val, tmp, TRACE_ARGV_CAP, &n, NULL) != 0)
			return -1;
		bool file_sys = false, file_func = false;
		for (int i = 0; i < n; i++) {
			if (tmp[i].kind == SPEC_KIND_FUNCS) file_func = true;
			else if (tmp[i].kind == SPEC_KIND_SYSCALL || tmp[i].kind == SPEC_KIND_LIB) file_sys = true;
			// SPEC_KIND_MOD: trace doesn't compose mod; silently not routed,
			// same as any engine that doesn't understand a kind line.
		}
		if (!file_sys && !file_func)
			fprintf(stderr, "trace: -F %s has no funcs:/syscall:/lib: lines for trace's "
			                "engines; ignored\n", spec->val);
		if (file_func) {
			*want_func = true;
			trace_tok_push(ta->func_toks, &ta->func_ntok, "funcs", (char *)flag);
			trace_tok_push(ta->func_toks, &ta->func_ntok, "funcs", spec->val);
		}
		if (file_sys) {
			*want_sys = true;
			trace_tok_push(ta->sys_toks, &ta->sys_ntok, "syscalls", (char *)flag);
			trace_tok_push(ta->sys_toks, &ta->sys_ntok, "syscalls", spec->val);
		}
		return 0;
	}

	custom_probe_spec_t one;
	if (parse_custom_probe_spec(spec->val, &one, NULL) != 0)
		return -1;
	switch (one.kind) {
	case SPEC_KIND_FUNCS:
		*want_func = true;
		trace_tok_push(ta->func_toks, &ta->func_ntok, "funcs", (char *)flag);
		trace_tok_push(ta->func_toks, &ta->func_ntok, "funcs", spec->val);
		break;
	case SPEC_KIND_SYSCALL:
	case SPEC_KIND_LIB:
		*want_sys = true;
		trace_tok_push(ta->sys_toks, &ta->sys_ntok, "syscalls", (char *)flag);
		trace_tok_push(ta->sys_toks, &ta->sys_ntok, "syscalls", spec->val);
		break;
	case SPEC_KIND_MOD:
		fprintf(stderr, "trace: 'mod:' is not a trace engine; run `anubee mod` standalone\n");
		return -1;
	}
	return 0;
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
	int  (*setup)(int argc, char **argv, const struct anubee_run_ctx *rc);
	int  (*run)(volatile sig_atomic_t *stop);
	void (*teardown)(void);

	// Filled in by cmd_trace before use:
	char **toks; int ntok;   // this engine's accumulated argv tokens (into trace_args)
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

	if (!pkg && !pids) {
		fprintf(stderr, "trace: one of -P <package> / -p <pid[,...]> is required\n");
		usage(argv[0]); return 1;
	}

	// Classify every collected top-level -e/-F spec by KIND and route it (see
	// classify_spec's doc comment) — this is what lets a bare `-e 'syscall:x'`
	// or `-e 'libc.so!x'` enable and feed the right engine with no --syscalls/
	// --funcs marker. May raise ta.want_sys/want_func on top of whatever the
	// flat parse already set from -a/-s/-x/-l or -S/-c.
	for (int i = 0; i < ta.nspec; i++) {
		if (classify_spec(&ta, &ta.specs[i], &ta.want_sys, &ta.want_func) != 0) {
			fprintf(stderr, "trace: bad %s '%s'\n", ta.specs[i].is_file ? "-F" : "-e",
			        ta.specs[i].val);
			return 1;
		}
	}

	engines[0].want = ta.want_sys;  engines[0].toks = ta.sys_toks;  engines[0].ntok = ta.sys_ntok;
	engines[1].want = ta.want_func; engines[1].toks = ta.func_toks; engines[1].ntok = ta.func_ntok;
	engines[2].want = ta.want_lib;  engines[2].toks = ta.lib_toks;  engines[2].ntok = ta.lib_ntok;

	bool any_want = false;
	for (int k = 0; k < NUM_ENGINES; k++)
		any_want = any_want || engines[k].want;
	if (!any_want) {
		fprintf(stderr, "trace: no engine enabled — need a syscalls/funcs-unique flag, a "
		                "routed -e/-F spec, or --lib\n");
		usage(argv[0]); return 1;
	}
	if (!prefix)
		fprintf(stderr, "trace: no -o; the engines' console output will interleave "
		                "— use -o <prefix> for clean per-engine JSONL\n");

	int uid = 0;
	if (pkg) {
		uid = anubee_resolve_uid(pkg);
		if (uid < 0) {
			fprintf(stderr, "trace: cannot resolve UID for '%s' (installed? run as root?)\n", pkg);
			return 1;
		}
	}
	// -p attach mode: rc stays zeroed — each engine reads "-p <pids>" from its own
	// argv (injected below) and arms target_pids itself, same as standalone.
	struct anubee_run_ctx rc = { .uid = uid, .pkg = pkg };

	// Build each engine's argv: ["<engine>", ("-o" file)?, <accumulated tokens...>].
	// All engines read the package name from rc->pkg (pre-filled before argp_parse).
	for (int k = 0; k < NUM_ENGINES; k++) {
		struct engine *e = &engines[k];
		if (!e->want) continue;
		int tr = 0;
		e->argc = trace_build_argv(&e->v, e->name, prefix, e->suffix, e->toks, e->ntok, &tr);
		if (tr) fprintf(stderr, "trace: %s argument list truncated (too many args)\n", e->name);
		// -p attach mode: inject "-p <pids>" so the engine arms target_pids itself.
		if (pids && e->argc < TRACE_ARGV_CAP - 2) {
			e->v.argv[e->argc++] = "-p";
			e->v.argv[e->argc++] = (char *)pids;
			e->v.argv[e->argc]   = NULL;
		} else if (pids) {
			fprintf(stderr, "trace: %s argument list full; -p not injected (target unset)\n", e->name);
		}
		// SYM1 Phase 1: -o no longer implies -q inside the engine, so trace must
		// inject -q itself under -o (else its concurrent engines' stdout
		// interleaves unusably, per the warning above when -o is absent).
		if (prefix && e->argc < TRACE_ARGV_CAP - 1) {
			e->v.argv[e->argc++] = "-q";
			e->v.argv[e->argc]   = NULL;
		} else if (prefix) {
			fprintf(stderr, "trace: %s argument list full; -q not injected\n", e->name);
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

	anubee_install_stop_handler(&g_stop);

	if (pids) {
		// -p attach mode: engines already armed target_pids in setup above; there
		// is no launch (the target is already running).
		printf("trace: attaching to pid(s) %s\n", pids);
	} else {
		anubee_launch_banner(pkg, uid);
		pid_t pid;
		if (anubee_launch_app(pkg, activity, &pid) != 0) {
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
