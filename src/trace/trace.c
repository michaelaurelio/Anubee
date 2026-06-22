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

#include "common/launch.h"   // struct ares_run_ctx, ares_resolve_uid, ares_launch_app

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
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s -P <package> [-o <prefix>] [--syscalls <args...>] [--funcs <args...>]\n"
		"\n"
		"Run the kprobe syscall tracer and the uprobe function tracer together from a\n"
		"single app launch (LOUD: the uprobe writes a BRK into the target).\n"
		"\n"
		"  -P <package>    app to launch and trace (required)\n"
		"  -o <prefix>     write <prefix>.syscalls.jsonl and <prefix>.funcs.jsonl\n"
		"                  (recommended: keeps the two structured streams separate and\n"
		"                  silences the syscalls console output)\n"
		"  --syscalls ...  options for the syscalls engine, e.g. '-a' or '<lib> -s openat'\n"
		"                  (no package — it comes from -P)\n"
		"  --funcs ...     options for the funcs engine, e.g. \"-e 'libc.so!open' -J\"\n"
		"                  (no -P — the package comes from -P above)\n"
		"\n"
		"-P and -o must come before the --syscalls / --funcs sections.\n",
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
	const char *pkg = NULL, *prefix = NULL;
	int sys_start = -1, sys_end = -1, func_start = -1, func_end = -1;

	// Coordinator-level flags up front, then the two engine sections. A section
	// runs until the next section delimiter or the end of argv.
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-P")) {
			if (++i >= argc) { usage(argv[0]); return 1; }
			pkg = argv[i];
		} else if (!strcmp(argv[i], "-o")) {
			if (++i >= argc) { usage(argv[0]); return 1; }
			prefix = argv[i];
		} else if (!strcmp(argv[i], "--syscalls")) {
			sys_start = i + 1; sys_end = argc;
			for (int j = sys_start; j < argc; j++)
				if (!strcmp(argv[j], "--funcs")) { sys_end = j; break; }
			i = sys_end - 1;
		} else if (!strcmp(argv[i], "--funcs")) {
			func_start = i + 1; func_end = argc;
			for (int j = func_start; j < argc; j++)
				if (!strcmp(argv[j], "--syscalls")) { func_end = j; break; }
			i = func_end - 1;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]); return 0;
		} else {
			fprintf(stderr, "trace: unexpected argument '%s' (did -P/-o come before the sections?)\n", argv[i]);
			usage(argv[0]); return 1;
		}
	}

	if (!pkg) { fprintf(stderr, "trace: -P <package> is required\n"); usage(argv[0]); return 1; }
	int want_sys = (sys_start >= 0), want_func = (func_start >= 0);
	if (!want_sys && !want_func) {
		fprintf(stderr, "trace: at least one of --syscalls / --funcs is required\n");
		usage(argv[0]); return 1;
	}

	int uid = ares_resolve_uid(pkg);
	if (uid < 0) {
		fprintf(stderr, "trace: cannot resolve UID for '%s' (installed? run as root?)\n", pkg);
		return 1;
	}
	struct ares_run_ctx rc = { .uid = uid, .pkg = pkg, .external_launch = 1 };

	// Build each engine's argv: ["<engine>", (-o <file>)?, <section args...>].
	char sysout[512], funcout[512];
	char *sys_argv[64]; int sys_argc = 0;
	char *func_argv[64]; int func_argc = 0;

	if (want_sys) {
		sys_argv[sys_argc++] = "syscalls";
		if (prefix) {
			snprintf(sysout, sizeof(sysout), "%s.syscalls.jsonl", prefix);
			sys_argv[sys_argc++] = "-o";
			sys_argv[sys_argc++] = sysout;
		}
		for (int i = sys_start; i < sys_end && sys_argc < 63; i++)
			sys_argv[sys_argc++] = argv[i];
		sys_argv[sys_argc] = NULL;
	}
	if (want_func) {
		func_argv[func_argc++] = "funcs";
		if (prefix) {
			snprintf(funcout, sizeof(funcout), "%s.funcs.jsonl", prefix);
			func_argv[func_argc++] = "-o";
			func_argv[func_argc++] = funcout;
		}
		for (int i = func_start; i < func_end && func_argc < 63; i++)
			func_argv[func_argc++] = argv[i];
		func_argv[func_argc] = NULL;
	}

	// Arm both engines BEFORE the single launch. Neither launches on its own —
	// setup only opens/loads/attaches and installs the UID filter (via rc->uid).
	if (want_sys && syscalls_setup(sys_argc, sys_argv, &rc) != 0) {
		fprintf(stderr, "trace: syscalls setup failed\n");
		return 1;
	}
	if (want_func && funcs_setup(func_argc, func_argv, &rc) != 0) {
		fprintf(stderr, "trace: funcs setup failed\n");
		if (want_sys) syscalls_teardown();
		return 1;
	}

	signal(SIGINT, on_sigint);

	printf("trace: launching %s (uid %d) — Ctrl-C to stop\n", pkg, uid);
	if (ares_launch_app(pkg, NULL) != 0) {
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
