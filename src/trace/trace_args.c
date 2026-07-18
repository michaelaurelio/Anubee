// SPDX-License-Identifier: GPL-2.0
#include "trace/trace_args.h"
#include <stdio.h>
#include <string.h>

int trace_build_argv(struct trace_argv *out, const char *engine,
                     const char *prefix, const char *suffix,
                     char **toks, int ntok, int *truncated)
{
	int argc = 0;
	if (truncated) *truncated = 0;

	out->argv[argc++] = (char *)engine;
	if (prefix) {
		snprintf(out->outbuf, sizeof(out->outbuf), "%s.%s", prefix, suffix);
		out->argv[argc++] = "-o";
		out->argv[argc++] = out->outbuf;
	}
	int i = 0;
	for (; i < ntok && argc < TRACE_ARGV_CAP - 1; i++)
		out->argv[argc++] = toks[i];
	if (i < ntok && truncated)
		*truncated = 1;
	out->argv[argc] = NULL;
	return argc;
}

// Flags with no value, broadcast to every engine that understands them
// (syscalls, funcs, and lib all share -v/-q). --siblings/--no-follow-fork are
// handled separately below (deferred until we know launch vs attach mode).
static int is_common_flag(const char *s)
{
	return !strcmp(s, "-v") || !strcmp(s, "-q");
}

// Flags shared by syscalls+funcs only (lib has neither -b/-Q nor snapshots).
static int is_sys_func_flag_noval(const char *s)
{
	return !strcmp(s, "--snapshot") || !strcmp(s, "--no-snapshot");
}
static int is_sys_func_flag_val(const char *s)
{
	return !strcmp(s, "-b") || !strcmp(s, "-Q");
}

// syscalls-unique flags: presence enables syscalls.
static int is_sys_flag_val(const char *s)
{
	return !strcmp(s, "-s") || !strcmp(s, "-x") || !strcmp(s, "-l");
}

// funcs-unique flags: presence enables funcs.
static int is_func_flag_noval(const char *s) { return !strcmp(s, "-S") || !strcmp(s, "-c"); }

int trace_parse_args(int argc, char **argv, struct trace_args *o)
{
	memset(o, 0, sizeof(*o));

	for (int i = 1; i < argc; i++) {
		char *tok = argv[i];

		if (!strcmp(tok, "-P")) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			if (o->pids) { fprintf(stderr, "trace: -P and -p are mutually exclusive\n"); return -1; }
			o->pkg = argv[i];
		} else if (!strcmp(tok, "-p")) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			if (o->pkg) { fprintf(stderr, "trace: -P and -p are mutually exclusive\n"); return -1; }
			o->pids = argv[i];
		} else if (!strcmp(tok, "-A")) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			o->activity = argv[i];
		} else if (!strcmp(tok, "-o")) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			o->prefix = argv[i];
		} else if (!strcmp(tok, "-e") || !strcmp(tok, "-F")) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			if (o->nspec >= TRACE_ARGV_CAP) {
				fprintf(stderr, "trace: too many -e/-F specs; '%s' dropped\n", argv[i]);
				continue;
			}
			o->specs[o->nspec].val = argv[i];
			o->specs[o->nspec].is_file = !strcmp(tok, "-F");
			o->nspec++;
		} else if (!strcmp(tok, "--lib")) {
			o->want_lib = true;
		} else if (!strcmp(tok, "--siblings")) {
			o->siblings = 1;
		} else if (!strcmp(tok, "--no-follow-fork")) {
			o->no_follow = 1;
		} else if (is_common_flag(tok)) {
			trace_tok_push(o->sys_toks, &o->sys_ntok, "syscalls", tok);
			trace_tok_push(o->func_toks, &o->func_ntok, "funcs", tok);
			trace_tok_push(o->lib_toks, &o->lib_ntok, "lib", tok);
		} else if (is_sys_func_flag_noval(tok)) {
			trace_tok_push(o->sys_toks, &o->sys_ntok, "syscalls", tok);
			trace_tok_push(o->func_toks, &o->func_ntok, "funcs", tok);
		} else if (is_sys_func_flag_val(tok)) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			trace_tok_push(o->sys_toks, &o->sys_ntok, "syscalls", tok);
			trace_tok_push(o->sys_toks, &o->sys_ntok, "syscalls", argv[i]);
			trace_tok_push(o->func_toks, &o->func_ntok, "funcs", tok);
			trace_tok_push(o->func_toks, &o->func_ntok, "funcs", argv[i]);
		} else if (!strcmp(tok, "--syscalls")) {
			o->want_sys = true;
		} else if (is_sys_flag_val(tok)) {
			if (++i >= argc) { fprintf(stderr, "trace: '%s' requires a value\n", tok); return -1; }
			trace_tok_push(o->sys_toks, &o->sys_ntok, "syscalls", tok);
			trace_tok_push(o->sys_toks, &o->sys_ntok, "syscalls", argv[i]);
			o->want_sys = true;
		} else if (is_func_flag_noval(tok)) {
			trace_tok_push(o->func_toks, &o->func_ntok, "funcs", tok);
			o->want_func = true;
		} else if (!strcmp(tok, "-h") || !strcmp(tok, "--help")) {
			return 1;
		} else {
			fprintf(stderr, "trace: unrecognized argument '%s'\n", tok);
			return -1;
		}
	}

	// Fix E: --siblings/--no-follow-fork mean nothing without -p. In attach mode
	// forward them to every engine that understands them; in launch mode warn
	// once here rather than letting each engine's ARGP_KEY_END warn separately.
	if (o->siblings || o->no_follow) {
		if (o->pids) {
			if (o->siblings) {
				trace_tok_push(o->sys_toks,  &o->sys_ntok,  "syscalls", "--siblings");
				trace_tok_push(o->func_toks, &o->func_ntok, "funcs",    "--siblings");
				trace_tok_push(o->lib_toks,  &o->lib_ntok,  "lib",      "--siblings");
			}
			if (o->no_follow) {
				trace_tok_push(o->sys_toks,  &o->sys_ntok,  "syscalls", "--no-follow-fork");
				trace_tok_push(o->func_toks, &o->func_ntok, "funcs",    "--no-follow-fork");
				trace_tok_push(o->lib_toks,  &o->lib_ntok,  "lib",      "--no-follow-fork");
			}
		} else {
			fprintf(stderr, "trace: warning - --siblings/--no-follow-fork need -p; ignored\n");
		}
	}
	return 0;
}
