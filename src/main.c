// SPDX-License-Identifier: GPL-2.0
// ares — unified Android RASP / malware-analysis tracer.
//
// One binary, two tracing engines selected by subcommand. Each engine loads ONLY
// its own BPF object, so the stealthy kprobe syscall tracer ("syscalls") can run
// without the detectable uprobe function tracer ("funcs") ever touching the
// target's memory. See DOCUMENTATION.md for the detectability rationale.
#include <stdio.h>
#include <string.h>

// Engine entry points (renamed from each tool's former main()).
int cmd_syscalls(int argc, char **argv);   // src/syscalls/heimdall.c
int cmd_funcs(int argc, char **argv);      // src/funcs/ares-tracer.c
int cmd_lib(int argc, char **argv);        // src/lib/lib.c
int cmd_dump(int argc, char **argv);       // src/dump/dump.c

static void usage(const char *argv0)
{
	fprintf(stderr,
		"ares — Android RASP / malware analysis tracer\n"
		"\n"
		"usage: %s <command> [args...]\n"
		"\n"
		"commands:\n"
		"  syscalls        kprobe syscall tracer, filtered by stack-origin library\n"
		"                  (injectionless / stealthy). Traces Java + native layers.\n"
		"  funcs           uprobe function tracer, spec-driven. Writes BRK into the\n"
		"                  target (detectable). Modules: proc / execve / getprop.\n"
		"  lib             library-load tracer: launch an app and list every native\n"
		"                  library (.so) it loads (injectionless / stealthy).\n"
		"  dump            launch an app and dump a (possibly decrypted) native\n"
		"                  library from live memory, rebuilt into a loadable ELF.\n"
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

	fprintf(stderr, "%s: unknown command '%s'\n\n", argv[0], cmd);
	usage(argv[0]);
	return 1;
}
