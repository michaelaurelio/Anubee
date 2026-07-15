// SPDX-License-Identifier: GPL-2.0
// Host check for the `ares trace` flat flag router and argv builder.
// Markers (--syscalls/--funcs/--lib sections) are gone: every flag is
// recognized by its own letter/name; KIND-routing of -e/-F specs (which
// engine funcs:/syscall:/lib:/mod: land on) happens in trace.c, which links
// against the ELF-aware probe-spec parser, so it isn't exercised here — this
// file only proves the ELF-free collection/routing layer trace_parse_args
// itself owns.
#include "trace/trace_args.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define A(s) ((char *)(s))

// Count occurrences of `tok` in a token accumulator.
static int count_tok(char **toks, int n, const char *tok)
{
	int c = 0;
	for (int i = 0; i < n; i++)
		if (!strcmp(toks[i], tok)) c++;
	return c;
}

int main(void)
{
	struct trace_args t;

	// --- globals: -P/-o/-A parsed, no engine flags -> parses OK, nothing wants ---
	char *a[] = { A("trace"), A("-P"), A("pkg"), A("-o"), A("run"), A("-A"), A("act") };
	assert(trace_parse_args(7, a, &t) == 0);
	assert(strcmp(t.pkg, "pkg") == 0);
	assert(strcmp(t.prefix, "run") == 0);
	assert(strcmp(t.activity, "act") == 0);
	assert(!t.want_sys && !t.want_func && !t.want_lib);
	assert(t.sys_ntok == 0 && t.func_ntok == 0 && t.lib_ntok == 0 && t.nspec == 0);

	// -p attach mode, mutually exclusive with -P either order (unchanged from
	// the section-splitter era, just no --syscalls marker needed anymore)
	char *pmode[] = { A("trace"), A("-p"), A("123,456") };
	assert(trace_parse_args(3, pmode, &t) == 0);
	assert(t.pkg == NULL && strcmp(t.pids, "123,456") == 0);
	char *j[] = { A("trace"), A("-P"), A("pkg"), A("-p"), A("1") };
	assert(trace_parse_args(5, j, &t) < 0);          // -P then -p: rejected
	char *k[] = { A("trace"), A("-p"), A("1"), A("-P"), A("pkg") };
	assert(trace_parse_args(5, k, &t) < 0);          // -p then -P: rejected too

	// --- syscalls-unique flags: route to sys_toks, enable syscalls only ---
	char *b[] = { A("trace"), A("-P"), A("pkg"), A("-a") };
	assert(trace_parse_args(4, b, &t) == 0);
	assert(t.want_sys && !t.want_func && !t.want_lib);
	assert(t.sys_ntok == 1 && !strcmp(t.sys_toks[0], "-a"));
	assert(t.func_ntok == 0 && t.lib_ntok == 0);

	char *slist[] = { A("trace"), A("-P"), A("pkg"), A("-s"), A("openat,read"),
	                  A("-x"), A("ptrace"), A("-l"), A("libfoo*") };
	assert(trace_parse_args(9, slist, &t) == 0);
	assert(t.want_sys && !t.want_func);
	assert(count_tok(t.sys_toks, t.sys_ntok, "-s") == 1);
	assert(count_tok(t.sys_toks, t.sys_ntok, "openat,read") == 1);
	assert(count_tok(t.sys_toks, t.sys_ntok, "-x") == 1);
	assert(count_tok(t.sys_toks, t.sys_ntok, "-l") == 1);
	assert(t.func_ntok == 0);

	// --- funcs-unique flags: route to func_toks, enable funcs only ---
	char *c[] = { A("trace"), A("-P"), A("pkg"), A("-S"), A("-c") };
	assert(trace_parse_args(5, c, &t) == 0);
	assert(t.want_func && !t.want_sys && !t.want_lib);
	assert(count_tok(t.func_toks, t.func_ntok, "-S") == 1);
	assert(count_tok(t.func_toks, t.func_ntok, "-c") == 1);
	assert(t.sys_ntok == 0);

	// --- --lib toggle: enables lib, no tokens needed ---
	char *lib[] = { A("trace"), A("-P"), A("pkg"), A("--lib") };
	assert(trace_parse_args(4, lib, &t) == 0);
	assert(t.want_lib && !t.want_sys && !t.want_func);
	assert(t.lib_ntok == 0);

	// --- broadcast common flags (-v/-q/--siblings/--no-follow-fork): land on
	//     all three accumulators, do NOT themselves set any want_* ---
	char *v[] = { A("trace"), A("-P"), A("pkg"), A("-v"), A("-q"),
	              A("--siblings"), A("--no-follow-fork") };
	assert(trace_parse_args(7, v, &t) == 0);
	assert(!t.want_sys && !t.want_func && !t.want_lib);   // broadcast alone enables nothing
	for (int i = 0; i < 4; i++) {
		const char *f = (const char *[]){ "-v", "-q", "--siblings", "--no-follow-fork" }[i];
		assert(count_tok(t.sys_toks, t.sys_ntok, f) == 1);
		assert(count_tok(t.func_toks, t.func_ntok, f) == 1);
		assert(count_tok(t.lib_toks, t.lib_ntok, f) == 1);
	}

	// --- -b/-Q: broadcast to syscalls+funcs only, NEVER lib (lib has no -b/-Q) ---
	char *bq[] = { A("trace"), A("-P"), A("pkg"), A("-b"), A("8"), A("-Q"), A("16") };
	assert(trace_parse_args(7, bq, &t) == 0);
	assert(!t.want_sys && !t.want_func);   // -b/-Q alone don't enable an engine
	assert(count_tok(t.sys_toks, t.sys_ntok, "-b") == 1 && count_tok(t.sys_toks, t.sys_ntok, "8") == 1);
	assert(count_tok(t.func_toks, t.func_ntok, "-b") == 1 && count_tok(t.func_toks, t.func_ntok, "8") == 1);
	assert(count_tok(t.sys_toks, t.sys_ntok, "-Q") == 1 && count_tok(t.func_toks, t.func_ntok, "-Q") == 1);
	assert(t.lib_ntok == 0);   // lib never receives -b/-Q

	// --- --snapshot/--no-snapshot: broadcast to syscalls+funcs only, no lib ---
	char *snap[] = { A("trace"), A("-P"), A("pkg"), A("-a"), A("--snapshot") };
	assert(trace_parse_args(5, snap, &t) == 0);
	assert(t.want_sys);   // from -a; --snapshot itself doesn't enable anything
	assert(count_tok(t.sys_toks, t.sys_ntok, "--snapshot") == 1);
	assert(count_tok(t.func_toks, t.func_ntok, "--snapshot") == 1);
	assert(t.lib_ntok == 0);

	// --- -e/-F: collected into specs[], NOT classified/routed here (that's
	//     trace.c's job, since it needs the ELF-aware spec parser) ---
	char *specs[] = { A("trace"), A("-P"), A("pkg"), A("-e"), A("syscall:openat"),
	                  A("-e"), A("libc.so!open"), A("-F"), A("my.spec") };
	assert(trace_parse_args(9, specs, &t) == 0);
	assert(!t.want_sys && !t.want_func);   // unclassified at this layer
	assert(t.nspec == 3);
	assert(!strcmp(t.specs[0].val, "syscall:openat") && !t.specs[0].is_file);
	assert(!strcmp(t.specs[1].val, "libc.so!open") && !t.specs[1].is_file);
	assert(!strcmp(t.specs[2].val, "my.spec") && t.specs[2].is_file);

	// --- errors / help ---
	char *d[] = { A("trace"), A("-P") };
	assert(trace_parse_args(2, d, &t) < 0);          // -P missing value
	char *e[] = { A("trace"), A("--help") };
	assert(trace_parse_args(2, e, &t) == 1);
	char *f[] = { A("trace"), A("bogus") };
	assert(trace_parse_args(2, f, &t) < 0);          // unrecognized token
	char *g[] = { A("trace"), A("-e") };
	assert(trace_parse_args(2, g, &t) < 0);          // -e missing value
	char *h[] = { A("trace"), A("-s") };
	assert(trace_parse_args(2, h, &t) < 0);          // -s missing value

	// --- combined: multiple engines enabled at once, no markers anywhere ---
	char *combo[] = { A("trace"), A("-P"), A("pkg"), A("-o"), A("run"), A("-a"),
	                  A("-e"), A("libc.so!open"), A("--lib") };
	assert(trace_parse_args(9, combo, &t) == 0);
	assert(t.want_sys && !t.want_func && t.want_lib);   // -e not yet classified -> want_func false here
	assert(t.nspec == 1);

	// --- trace_build_argv (now takes a flat token array, no argv-slice indices) ---
	struct trace_argv tv;

	// syscalls, no prefix
	char *s1[] = { A("-a") };
	int na = trace_build_argv(&tv, "syscalls", NULL, NULL, s1, 1, NULL);
	assert(na == 2);
	assert(strcmp(tv.argv[0], "syscalls") == 0);
	assert(strcmp(tv.argv[1], "-a") == 0);
	assert(tv.argv[2] == NULL);

	// funcs, with prefix (package now comes from rc, not injected into argv)
	char *s2[] = { A("-e"), A("lib!fn") };
	int trunc = 0;
	int nb = trace_build_argv(&tv, "funcs", "run", "funcs.jsonl", s2, 2, &trunc);
	assert(trunc == 0);
	assert(nb == 5);  // engine + -o file + 2 tokens
	assert(strcmp(tv.argv[0], "funcs") == 0);
	assert(strcmp(tv.argv[1], "-o") == 0);
	assert(strcmp(tv.argv[2], "run.funcs.jsonl") == 0);
	assert(strcmp(tv.argv[3], "-e") == 0 && strcmp(tv.argv[4], "lib!fn") == 0);
	assert(tv.argv[5] == NULL);

	// empty token list — only header entries
	int nc = trace_build_argv(&tv, "syscalls", NULL, NULL, s1, 0, NULL);
	assert(nc == 1 && strcmp(tv.argv[0], "syscalls") == 0 && tv.argv[1] == NULL);

	// truncation: fill past 63-arg limit
	char *big[128]; for (int i = 0; i < 128; i++) big[i] = A("x");
	trunc = 0;
	int nd = trace_build_argv(&tv, "syscalls", NULL, NULL, big, 128, &trunc);
	assert(trunc == 1);
	assert(nd == 63);         // 1 engine name + 62 tokens
	assert(tv.argv[63] == NULL);

	// injection-overflow boundary (F2, preserved verbatim from the section
	// era): trace.c injects "-p <pids>" (2 argv slots + NULL) right after
	// trace_build_argv returns, guarded by "argc < TRACE_ARGV_CAP - 2" so the
	// inject always has room for those 2 slots.
	char *cap[TRACE_ARGV_CAP]; for (int i = 0; i < TRACE_ARGV_CAP; i++) cap[i] = A("x");

	trunc = 0;
	int ne = trace_build_argv(&tv, "syscalls", NULL, NULL, cap, TRACE_ARGV_CAP - 3, &trunc);
	assert(trunc == 0);
	assert(ne == TRACE_ARGV_CAP - 2);

	trunc = 0;
	int nf = trace_build_argv(&tv, "syscalls", NULL, NULL, cap, TRACE_ARGV_CAP - 2, &trunc);
	assert(trunc == 0);
	assert(nf == TRACE_ARGV_CAP - 1);

	trunc = 0;
	int ng = trace_build_argv(&tv, "syscalls", NULL, NULL, cap, TRACE_ARGV_CAP - 1, &trunc);
	assert(trunc == 1);
	assert(ng == TRACE_ARGV_CAP - 1);

	// --- trace_tok_push: bounds-checked accumulator append, shared by
	//     trace_parse_args above and trace.c's spec-classification injection ---
	char *toks[TRACE_ARGV_CAP]; int ntok = 0;
	for (int i = 0; i < TRACE_ARGV_CAP - 1; i++)
		assert(trace_tok_push(toks, &ntok, "test", A("x")) == true);
	assert(ntok == TRACE_ARGV_CAP - 1);
	assert(trace_tok_push(toks, &ntok, "test", A("overflow")) == false);  // full, dropped
	assert(ntok == TRACE_ARGV_CAP - 1);   // unchanged

	printf("trace_args: ok\n");
	return 0;
}
