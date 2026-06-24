// SPDX-License-Identifier: GPL-2.0
//
// ares trace — run the kprobe (syscalls) and uprobe (funcs) engines together
// from a SINGLE app launch. This is a thin coordinator: it reuses each engine's
// setup/run/teardown phases unchanged, arms both before the one launch, then
// drains both ring buffers concurrently. It is inherently LOUD — the uprobe
// engine writes a BRK into the target — so it never sits on the stealthy side of
// the detectability firewall. See DOCUMENTATION.md / BACKLOG.md.
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "common/launch.h"   // struct ares_run_ctx, ares_resolve_uid, ares_launch_app
#include "trace/trace_args.h"

// Engine driver entry points. Defined in the syscalls / funcs engines and kept
// global through their partial-link (see the --keep-global-symbol lists in the
// Makefile). Declared here directly to avoid pulling in each engine's header.
int  syscalls_setup(int argc, char **argv, const struct ares_run_ctx *rc);
int  syscalls_run(volatile sig_atomic_t *stop);
void syscalls_teardown(void);
int  funcs_setup(int argc, char **argv, const struct ares_run_ctx *rc);
int  funcs_run(volatile sig_atomic_t *stop);
void funcs_teardown(void);

// One stop flag shared by both engines' poll loops; set by the coordinator's
// SIGINT handler (the engines do not install their own when driven here).
static volatile sig_atomic_t g_stop;
static void on_sigint(int sig) { (void)sig; if (g_stop) _exit(130); g_stop = 1; }

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s -P <package> [-o <prefix>] [--syscalls <args...>] [--funcs <args...>]\n"
		"\n"
		"Run the kprobe syscall tracer and the uprobe function tracer together from a\n"
		"single app launch (LOUD: the uprobe writes a BRK into the target).\n"
		"\n"
		"  -P <package>    app to launch and trace (required)\n"
		"  -A <activity>   override launch activity component (default: auto-resolve)\n"
		"  -o <prefix>     write <prefix>.syscalls.jsonl and <prefix>.funcs.jsonl\n"
		"                  (recommended: keeps the two structured streams separate and\n"
		"                  silences the syscalls console output)\n"
		"  --syscalls ...  options for the syscalls engine, e.g. '-a' or '<lib> -s openat'\n"
		"                  (no package — it comes from -P)\n"
		"  --funcs ...     options for the funcs engine, e.g. \"-e 'libc.so!open' -J\"\n"
		"                  (no -P — the package comes from -P above)\n"
		"\n"
		"-P, -A, and -o must come before the --syscalls / --funcs sections.\n",
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
	int sys_start = ta.sys_start, sys_end = ta.sys_end;
	int func_start = ta.func_start, func_end = ta.func_end;

	if (!pkg) { fprintf(stderr, "trace: -P <package> is required\n"); usage(argv[0]); return 1; }
	int want_sys = (sys_start >= 0), want_func = (func_start >= 0);
	if (!want_sys && !want_func) {
		fprintf(stderr, "trace: at least one of --syscalls / --funcs is required\n");
		usage(argv[0]); return 1;
	}
	if (!prefix)
		fprintf(stderr, "trace: no -o; the two engines' console output will interleave "
		                "— use -o <prefix> for clean per-engine JSONL\n");

	int uid = ares_resolve_uid(pkg);
	if (uid < 0) {
		fprintf(stderr, "trace: cannot resolve UID for '%s' (installed? run as root?)\n", pkg);
		return 1;
	}
	struct ares_run_ctx rc = { .uid = uid, .pkg = pkg };

	// Build each engine's argv: ["<engine>", ("-o" file)?, <section args...>].
	// Both engines read the package name from rc->pkg (pre-filled before argp_parse).
	struct trace_argv sysv, funcv;
	int sys_argc = 0, func_argc = 0;

	if (want_sys) {
		int tr = 0;
		sys_argc = trace_build_argv(&sysv, "syscalls", prefix,
		                            "syscalls.jsonl", argv, sys_start, sys_end, &tr);
		if (tr) fprintf(stderr, "trace: --syscalls section truncated (too many args)\n");
	}
	if (want_func) {
		int tr = 0;
		func_argc = trace_build_argv(&funcv, "funcs", prefix,
		                             "funcs.jsonl", argv, func_start, func_end, &tr);
		if (tr) fprintf(stderr, "trace: --funcs section truncated (too many args)\n");
		// ponytail: -o implies quiet in syscalls; mirror that for funcs under trace
		// so "trace -o prefix" silences both engines' consoles symmetrically.
		if (prefix && func_argc < 63) {
			funcv.argv[func_argc++] = "-q";
			funcv.argv[func_argc]   = NULL;
		}
	}

	// Arm both engines BEFORE the single launch. Neither launches on its own —
	// setup only opens/loads/attaches and installs the UID filter (via rc->uid).
	if (want_sys && syscalls_setup(sys_argc, sysv.argv, &rc) != 0) {
		fprintf(stderr, "trace: syscalls setup failed\n");
		return 1;
	}
	if (want_func && funcs_setup(func_argc, funcv.argv, &rc) != 0) {
		fprintf(stderr, "trace: funcs setup failed\n");
		if (want_sys) syscalls_teardown();
		return 1;
	}

	signal(SIGINT, on_sigint);

	ares_launch_banner(pkg, uid);
	if (ares_launch_app(pkg, activity) != 0) {
		fprintf(stderr, "trace: launch failed for '%s'\n", pkg);
		if (want_func) funcs_teardown();
		if (want_sys) syscalls_teardown();
		return 1;
	}

	// Drain both ring buffers concurrently until Ctrl-C. Each engine uses its own
	// (symbol-localized) globals and its own ring buffer, so the threads do not
	// contend; the only shared state is g_stop.
	pthread_t sys_th, func_th;
	struct run_arg sa = { .run = syscalls_run };
	struct run_arg fa = { .run = funcs_run };
	int sys_th_ok = 0, func_th_ok = 0;

	if (want_sys) sys_th_ok = (pthread_create(&sys_th, NULL, run_thread, &sa) == 0);
	if (want_func) func_th_ok = (pthread_create(&func_th, NULL, run_thread, &fa) == 0);

	// Fallback: if a thread failed to spawn, drain that engine inline.
	if (want_sys && !sys_th_ok) syscalls_run(&g_stop);
	if (want_func && !func_th_ok) funcs_run(&g_stop);

	if (sys_th_ok) pthread_join(sys_th, NULL);
	if (func_th_ok) pthread_join(func_th, NULL);

	if (want_func) funcs_teardown();
	if (want_sys) syscalls_teardown();
	return 0;
}
