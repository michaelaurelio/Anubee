// SPDX-License-Identifier: GPL-2.0
#include "trace/trace_args.h"
#include <stdio.h>
#include <string.h>

int trace_build_argv(struct trace_argv *out, const char *engine,
                     const char *prefix, const char *suffix,
                     char **src_argv, int start, int end,
                     int *truncated)
{
	int argc = 0;
	if (truncated) *truncated = 0;

	out->argv[argc++] = (char *)engine;
	if (prefix) {
		snprintf(out->outbuf, sizeof(out->outbuf), "%s.%s", prefix, suffix);
		out->argv[argc++] = "-o";
		out->argv[argc++] = out->outbuf;
	}
	int i = start;
	for (; i < end && argc < 63; i++)
		out->argv[argc++] = src_argv[i];
	if (i < end && truncated)
		*truncated = 1;
	out->argv[argc] = NULL;
	return argc;
}

// Returns 1 if s is a section-start delimiter, so each section's end-scan can
// stop at any other section (not just the one other delimiter from the 2-engine era).
static int is_section_delim(const char *s)
{
	return !strcmp(s, "--syscalls") || !strcmp(s, "--funcs") || !strcmp(s, "--lib");
}

int trace_parse_args(int argc, char **argv, struct trace_args *o)
{
	o->pkg = o->prefix = o->activity = NULL;
	o->sys_start = o->sys_end = o->func_start = o->func_end = -1;
	o->lib_start = o->lib_end = -1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-P")) {
			if (++i >= argc) return -1;
			o->pkg = argv[i];
		} else if (!strcmp(argv[i], "-A")) {
			if (++i >= argc) return -1;
			o->activity = argv[i];
		} else if (!strcmp(argv[i], "-o")) {
			if (++i >= argc) return -1;
			o->prefix = argv[i];
		} else if (!strcmp(argv[i], "--syscalls")) {
			o->sys_start = i + 1; o->sys_end = argc;
			for (int j = o->sys_start; j < argc; j++)
				if (is_section_delim(argv[j])) { o->sys_end = j; break; }
			i = o->sys_end - 1;
		} else if (!strcmp(argv[i], "--funcs")) {
			o->func_start = i + 1; o->func_end = argc;
			for (int j = o->func_start; j < argc; j++)
				if (is_section_delim(argv[j])) { o->func_end = j; break; }
			i = o->func_end - 1;
		} else if (!strcmp(argv[i], "--lib")) {
			o->lib_start = i + 1; o->lib_end = argc;
			for (int j = o->lib_start; j < argc; j++)
				if (is_section_delim(argv[j])) { o->lib_end = j; break; }
			i = o->lib_end - 1;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			return 1;
		} else {
			return -1;
		}
	}
	return 0;
}
