// SPDX-License-Identifier: GPL-2.0
//
// ares trace — run the kprobe (syscalls), uprobe (funcs), and library-load (lib)
// engines together from a SINGLE app launch. This is a thin coordinator: it
// reuses each engine's setup/run/teardown phases unchanged, arms all requested
// engines before the one launch, then drains their ring buffers concurrently.
// It is inherently LOUD — the uprobe engine writes a BRK into the target — so
// it never sits on the stealthy side of the detectability firewall. See
// DOCUMENTATION.md / BACKLOG.md.
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "common/launch.h"   // struct ares_run_ctx, ares_resolve_uid, ares_launch_app
#include "common/runtime.h"  // ares_install_stop_handler
#include "trace/trace_args.h"

// Engine driver entry points (syscalls_/funcs_/lib_ setup/run/teardown). Defined
// in their respective engines and kept global through the partial-link (see the
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
		"[--syscalls <args...>] [--funcs <args...>] [--lib] [--dump <args...>]\n"
		"\n"
		"Run the kprobe syscall tracer, uprobe function tracer, library-load tracer,\n"
		"and/or module dumper together from a single app launch (LOUD: the uprobe\n"
		"writes a BRK into the target if --funcs is used).\n"
		"\n"
		"  -P <package>    app to launch and trace (mutually exclusive with -p)\n"
		"  -p <pid[,...]>  attach to already-running PID(s) instead of launching\n"
		"                  (mutually exclusive with -P; each engine arms its own\n"
		"                  target_pids from this list, no UID resolve/launch)\n"
		"  -A <activity>   override launch activity component (default: auto-resolve)\n"
		"  -o <prefix>     write <prefix>.syscalls.jsonl, <prefix>.funcs.jsonl,\n"
		"                  <prefix>.lib.jsonl, and/or <prefix>.dump.jsonl (recommended:\n"
		"                  keeps engine streams separate and silences console output)\n"
		"  --syscalls ...  options for the syscalls engine, e.g. '-a' or '<lib> -s openat'\n"
		"                  (no package/PID args — they come from -P/-p above)\n"
		"  --funcs ...     options for the funcs engine, e.g. \"-e 'libc.so!open' -J\"\n"
		"                  (no package/PID args — they come from -P/-p above)\n"
		"  --lib           enable library-load tracing (takes no sub-options)\n"
		"  --dump ...      options for the dump engine, e.g. \"'libfoo*' -d /tmp/dumps\"\n"
		"                  (no package/PID args — they come from -P/-p above; dump's\n"
		"                  output is ELF images + an on-exit rescan, not a live stream,\n"
		"                  so it's a batch engine riding alongside the streaming ones)\n"
		"\n"
		"-P/-p, -A, and -o must come before the --syscalls / --funcs / --lib / --dump sections.\n",
		argv0);
}

struct run_arg { int (*run)(volatile sig_atomic_t *); };
static void *run_thread(void *p)
{
	struct run_arg *a = p;
	a->run(&g_stop);
	return NULL;
}

int cmd_trace(int argc, char **argv)
{
	struct trace_args ta;
	int pr = trace_parse_args(argc, argv, &ta);
	if (pr == 1) { usage(argv[0]); return 0; }   // -h/--help
	if (pr < 0)  { usage(argv[0]); return 1; }
	const char *pkg = ta.pkg, *prefix = ta.prefix, *activity = ta.activity;
	const char *pids = ta.pids;
	int sys_start = ta.sys_start, sys_end = ta.sys_end;
	int func_start = ta.func_start, func_end = ta.func_end;
	int lib_start = ta.lib_start, lib_end = ta.lib_end;
	int dump_start = ta.dump_start, dump_end = ta.dump_end;

	if (!pkg && !pids) {
		fprintf(stderr, "trace: one of -P <package> / -p <pid[,...]> is required\n");
		usage(argv[0]); return 1;
	}
	int want_sys = (sys_start >= 0), want_func = (func_start >= 0), want_lib = (lib_start >= 0);
	int want_dump = (dump_start >= 0);
	if (!want_sys && !want_func && !want_lib && !want_dump) {
		fprintf(stderr, "trace: at least one of --syscalls / --funcs / --lib / --dump is required\n");
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
	struct trace_argv sysv, funcv, libv, dumpv;
	int sys_argc = 0, func_argc = 0, lib_argc = 0, dump_argc = 0;

	if (want_sys) {
		int tr = 0;
		sys_argc = trace_build_argv(&sysv, "syscalls", prefix,
		                            "syscalls.jsonl", argv, sys_start, sys_end, &tr);
		if (tr) fprintf(stderr, "trace: --syscalls section truncated (too many args)\n");
		// -p attach mode: inject "-p <pids>" so the engine arms target_pids itself.
		if (pids && sys_argc < 62) {
			sysv.argv[sys_argc++] = "-p";
			sysv.argv[sys_argc++] = (char *)pids;
			sysv.argv[sys_argc]   = NULL;
		}
	}
	if (want_func) {
		int tr = 0;
		func_argc = trace_build_argv(&funcv, "funcs", prefix,
		                             "funcs.jsonl", argv, func_start, func_end, &tr);
		if (tr) fprintf(stderr, "trace: --funcs section truncated (too many args)\n");
		if (pids && func_argc < 62) {
			funcv.argv[func_argc++] = "-p";
			funcv.argv[func_argc++] = (char *)pids;
			funcv.argv[func_argc]   = NULL;
		}
		// ponytail: -o implies quiet in syscalls; mirror that for funcs under trace
		// so "trace -o prefix" silences both engines' consoles symmetrically.
		if (prefix && func_argc < 63) {
			funcv.argv[func_argc++] = "-q";
			funcv.argv[func_argc]   = NULL;
		}
	}
	if (want_lib) {
		int tr = 0;
		lib_argc = trace_build_argv(&libv, "lib", prefix,
		                            "lib.jsonl", argv, lib_start, lib_end, &tr);
		if (tr) fprintf(stderr, "trace: --lib section truncated (too many args)\n");
		if (pids && lib_argc < 62) {
			libv.argv[lib_argc++] = "-p";
			libv.argv[lib_argc++] = (char *)pids;
			libv.argv[lib_argc]   = NULL;
		}
		// Mirror funcs: -o implies quiet for lib too.
		if (prefix && lib_argc < 63) {
			libv.argv[lib_argc++] = "-q";
			libv.argv[lib_argc]   = NULL;
		}
	}
	if (want_dump) {
		int tr = 0;
		dump_argc = trace_build_argv(&dumpv, "dump", prefix,
		                             "dump.jsonl", argv, dump_start, dump_end, &tr);
		if (tr) fprintf(stderr, "trace: --dump section truncated (too many args)\n");
		// dump requires -P or -p in its own argv (unlike sys/func/lib, its ARGP_KEY_END
		// errors without one) — rc->pkg pre-fill covers launch mode, but attach mode
		// needs -p injected explicitly, same as the other engines above.
		if (pids && dump_argc < 62) {
			dumpv.argv[dump_argc++] = "-p";
			dumpv.argv[dump_argc++] = (char *)pids;
			dumpv.argv[dump_argc]   = NULL;
		}
		// Mirror funcs/lib: -o implies quiet for dump too.
		if (prefix && dump_argc < 63) {
			dumpv.argv[dump_argc++] = "-q";
			dumpv.argv[dump_argc]   = NULL;
		}
	}

	// Arm all requested engines BEFORE the single launch. None launch on their
	// own — setup only opens/loads/attaches and installs the UID filter (via rc->uid).
	if (want_sys && syscalls_setup(sys_argc, sysv.argv, &rc) != 0) {
		fprintf(stderr, "trace: syscalls setup failed\n");
		return 1;
	}
	if (want_func && funcs_setup(func_argc, funcv.argv, &rc) != 0) {
		fprintf(stderr, "trace: funcs setup failed\n");
		if (want_sys) syscalls_teardown();
		return 1;
	}
	if (want_lib && lib_setup(lib_argc, libv.argv, &rc) != 0) {
		fprintf(stderr, "trace: lib setup failed\n");
		if (want_func) funcs_teardown();
		if (want_sys) syscalls_teardown();
		return 1;
	}
	if (want_dump && dump_setup(dump_argc, dumpv.argv, &rc) != 0) {
		fprintf(stderr, "trace: dump setup failed\n");
		if (want_lib) lib_teardown();
		if (want_func) funcs_teardown();
		if (want_sys) syscalls_teardown();
		return 1;
	}

	ares_install_stop_handler(&g_stop);

	if (pids) {
		// -p attach mode: engines already armed target_pids in setup above; there
		// is no launch (the target is already running).
		printf("trace: attaching to pid(s) %s\n", pids);
	} else {
		ares_launch_banner(pkg, uid);
		if (ares_launch_app(pkg, activity, NULL) != 0) {
			fprintf(stderr, "trace: launch failed for '%s'\n", pkg);
			if (want_dump) dump_teardown();
			if (want_lib) lib_teardown();
			if (want_func) funcs_teardown();
			if (want_sys) syscalls_teardown();
			return 1;
		}
	}

	// Drain all ring buffers concurrently until Ctrl-C. Each engine has its own
	// ring buffer, but src/common/symbolize.c's caches are shared (single linked
	// copy, not symbol-localized) — sym_resolve/sym_flush_pid/cfi_unwind_snapshot
	// all serialize on symbolize.c's internal g_lock (AA1 fix, 2026-07-07), so the
	// two threads don't race on those globals despite calling into them concurrently.
	// The only state owned directly by this file is g_stop.
	pthread_t sys_th, func_th, lib_th, dump_th;
	struct run_arg sa = { .run = syscalls_run };
	struct run_arg fa = { .run = funcs_run };
	struct run_arg la = { .run = lib_run };
	struct run_arg da = { .run = dump_run };
	int sys_th_ok = 0, func_th_ok = 0, lib_th_ok = 0, dump_th_ok = 0;

	if (want_sys) sys_th_ok = (pthread_create(&sys_th, NULL, run_thread, &sa) == 0);
	if (want_func) func_th_ok = (pthread_create(&func_th, NULL, run_thread, &fa) == 0);
	if (want_lib) lib_th_ok = (pthread_create(&lib_th, NULL, run_thread, &la) == 0);
	if (want_dump) dump_th_ok = (pthread_create(&dump_th, NULL, run_thread, &da) == 0);

	// Fallback: if a thread failed to spawn, drain that engine inline.
	if (want_sys && !sys_th_ok) syscalls_run(&g_stop);
	if (want_func && !func_th_ok) funcs_run(&g_stop);
	if (want_lib && !lib_th_ok) lib_run(&g_stop);
	if (want_dump && !dump_th_ok) dump_run(&g_stop);

	if (sys_th_ok) pthread_join(sys_th, NULL);
	if (func_th_ok) pthread_join(func_th, NULL);
	if (lib_th_ok) pthread_join(lib_th, NULL);
	if (dump_th_ok) pthread_join(dump_th, NULL);

	if (want_dump) dump_teardown();
	if (want_lib) lib_teardown();
	if (want_func) funcs_teardown();
	if (want_sys) syscalls_teardown();
	return 0;
}
