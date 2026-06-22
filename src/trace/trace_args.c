// SPDX-License-Identifier: GPL-2.0
#include "trace/trace_args.h"
#include <string.h>

int trace_parse_args(int argc, char **argv, struct trace_args *o)
{
	o->pkg = o->prefix = NULL;
	o->sys_start = o->sys_end = o->func_start = o->func_end = -1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-P")) {
			if (++i >= argc) return -1;
			o->pkg = argv[i];
		} else if (!strcmp(argv[i], "-o")) {
			if (++i >= argc) return -1;
			o->prefix = argv[i];
		} else if (!strcmp(argv[i], "--syscalls")) {
			o->sys_start = i + 1; o->sys_end = argc;
			for (int j = o->sys_start; j < argc; j++)
				if (!strcmp(argv[j], "--funcs")) { o->sys_end = j; break; }
			i = o->sys_end - 1;
		} else if (!strcmp(argv[i], "--funcs")) {
			o->func_start = i + 1; o->func_end = argc;
			for (int j = o->func_start; j < argc; j++)
				if (!strcmp(argv[j], "--syscalls")) { o->func_end = j; break; }
			i = o->func_end - 1;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			return 1;
		} else {
			return -1;
		}
	}
	return 0;
}
