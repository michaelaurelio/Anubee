// SPDX-License-Identifier: GPL-2.0
// anubee — unified Android RASP / malware-analysis tracer.
//
// One binary, two tracing engines selected by subcommand. Each engine loads ONLY
// its own BPF object, so the stealthy kprobe syscall tracer ("syscalls") can run
// without the detectable uprobe function tracer ("funcs") ever touching the
// target's memory. See DOCUMENTATION.md for the detectability rationale.
#include <stdio.h>
#include <string.h>

// Engine entry points (renamed from each tool's former main()).
int cmd_syscalls(int argc, char **argv);   // src/syscalls/syscalls.c
int cmd_funcs(int argc, char **argv);      // src/funcs/funcs.c
int cmd_lib(int argc, char **argv);        // src/lib/lib.c
int cmd_dump(int argc, char **argv);       // src/dump/dump.c
int cmd_correlate(int argc, char **argv);  // src/correlate/correlate.c
int cmd_trace(int argc, char **argv);      // src/trace/trace.c
int cmd_mod(int argc, char **argv);        // src/modules/mod.c

static void usage(const char *argv0)
{
	fprintf(stderr,
		"anubee — Android RASP / malware analysis tracer\n"
		"\n"
		"usage: %s <command> [args...]\n"
		"\n"
		"commands:\n"
		"  syscalls        kprobe syscall tracer, filtered by stack-origin library\n"
		"                  (injectionless / stealthy). Traces Java + native layers.\n"
		"  funcs           uprobe function tracer, spec-driven. Writes BRK into the\n"
		"                  target (detectable).\n"
		"  lib             library-load tracer: launch an app and list every native\n"
		"                  library (.so) it loads (injectionless / stealthy).\n"
		"  dump            launch an app and dump a (possibly decrypted) native\n"
		"                  library from live memory, rebuilt into a loadable ELF.\n"
		"  correlate       function->syscall tracer: entry uprobes + a span-gated\n"
		"                  syscall kprobe (LOUD: writes BRK). Tags each in-span\n"
		"                  syscall with the enclosing function's span.\n"
		"  trace           run the syscalls (kprobe) and funcs (uprobe) engines\n"
		"                  together from one app launch (LOUD). Two independent\n"
		"                  streams, no correlation.\n"
		"  mod             run a named analyzer: specialized tracing package with its own\n"
		"                  BPF object. Stealthy or loud depending on the analyzer.\n"
		"                  `anubee mod --list` lists available analyzers.\n"
		"\n"
		"Run '%s <command> --help' for command-specific options.\n",
		argv0, argv0);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	const char *cmd = argv[1];
	if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
		usage(argv[0]);
		return 0;
	}

	// --version / -V: answered centrally because objcopy localizes each engine's
	// argp_program_version, leaving glibc's weak NULL fallback and a broken
	// --version. Print "anubee <subcommand>" and exit; guard on the known-name set
	// so "anubee bogus --version" still falls through to the "unknown command" error.
	static const char *known[] = { "syscalls","funcs","lib","dump","correlate","trace","mod" };
	for (int k = 0; k < (int)(sizeof(known)/sizeof(known[0])); k++) {
		if (strcmp(cmd, known[k])) continue;
		for (int i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-V")) {
				printf("anubee %s\n", cmd);
				return 0;
			}
		}
		break;
	}

	// Hand off the rest of argv past the subcommand. Each engine keeps its own
	// argument parser and sees argv[0] = the subcommand name (used in its usage).
	if (!strcmp(cmd, "syscalls"))
		return cmd_syscalls(argc - 1, argv + 1);
	if (!strcmp(cmd, "funcs"))
		return cmd_funcs(argc - 1, argv + 1);
	if (!strcmp(cmd, "lib"))
		return cmd_lib(argc - 1, argv + 1);
	if (!strcmp(cmd, "dump"))
		return cmd_dump(argc - 1, argv + 1);
	if (!strcmp(cmd, "correlate"))
		return cmd_correlate(argc - 1, argv + 1);
	if (!strcmp(cmd, "trace"))
		return cmd_trace(argc - 1, argv + 1);
	if (!strcmp(cmd, "mod"))
		return cmd_mod(argc - 1, argv + 1);

	fprintf(stderr, "%s: unknown command '%s'\n\n", argv[0], cmd);
	usage(argv[0]);
	return 1;
}
