// SPDX-License-Identifier: GPL-2.0
// Host check for the `ares trace` arg-section splitter and argv builder.
#include "trace/trace_args.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define A(s) ((char *)(s))

int main(void)
{
	struct trace_args t;

	// typical: -P pkg --syscalls -a --funcs -e x
	char *a[] = { A("trace"), A("-P"), A("pkg"), A("--syscalls"), A("-a"),
	              A("--funcs"), A("-e"), A("x") };
	assert(trace_parse_args(8, a, &t) == 0);
	assert(strcmp(t.pkg, "pkg") == 0 && t.prefix == NULL);
	assert(t.sys_start == 4 && t.sys_end == 5);     // "-a"
	assert(t.func_start == 6 && t.func_end == 8);   // "-e","x"

	// -o prefix, reversed section order
	char *b[] = { A("trace"), A("-o"), A("p"), A("--funcs"), A("-e"), A("y"),
	              A("--syscalls"), A("-a") };
	assert(trace_parse_args(8, b, &t) == 0);
	assert(strcmp(t.prefix, "p") == 0);
	assert(t.func_start == 4 && t.func_end == 6);
	assert(t.sys_start == 7 && t.sys_end == 8);

	// repeated --funcs: empty first section, last one wins (the real-world fumble)
	char *c[] = { A("trace"), A("-P"), A("p"), A("--funcs"), A("--syscalls"),
	              A("-a"), A("--funcs"), A("-e"), A("z") };
	assert(trace_parse_args(9, c, &t) == 0);
	assert(t.sys_start == 5 && t.sys_end == 6);
	assert(t.func_start == 7 && t.func_end == 9);

	// 3-section: --syscalls --funcs --lib in order
	char *g[] = { A("trace"), A("-P"), A("pkg"), A("--syscalls"), A("-a"),
	              A("--funcs"), A("-e"), A("x"), A("--lib") };
	assert(trace_parse_args(9, g, &t) == 0);
	assert(t.sys_start == 4 && t.sys_end == 5);    // "-a", stops at --funcs
	assert(t.func_start == 6 && t.func_end == 8);  // "-e","x", stops at --lib
	assert(t.lib_start == 9 && t.lib_end == 9);    // empty --lib section

	// 3-section: --lib before --syscalls (tests that old 2-delimiter scan would mis-split)
	char *h[] = { A("trace"), A("-P"), A("pkg"), A("--lib"), A("--syscalls"), A("-a"),
	              A("--funcs"), A("-e"), A("y") };
	assert(trace_parse_args(9, h, &t) == 0);
	assert(t.lib_start == 4 && t.lib_end == 4);    // empty, stops at --syscalls
	assert(t.sys_start == 5 && t.sys_end == 6);    // "-a", stops at --funcs
	assert(t.func_start == 7 && t.func_end == 9);  // "-e","y"

	// errors / help
	char *d[] = { A("trace"), A("-P") };
	assert(trace_parse_args(2, d, &t) < 0);          // -P missing value
	char *e[] = { A("trace"), A("--help") };
	assert(trace_parse_args(2, e, &t) == 1);
	char *f[] = { A("trace"), A("bogus") };
	assert(trace_parse_args(2, f, &t) < 0);          // unexpected token

	// -p attach mode (Phase 3d): parses, mutually exclusive with -P either order
	char *i[] = { A("trace"), A("-p"), A("123,456"), A("--syscalls"), A("-a") };
	assert(trace_parse_args(5, i, &t) == 0);
	assert(t.pkg == NULL && strcmp(t.pids, "123,456") == 0);
	assert(t.sys_start == 4 && t.sys_end == 5);

	char *j[] = { A("trace"), A("-P"), A("pkg"), A("-p"), A("1") };
	assert(trace_parse_args(5, j, &t) < 0);          // -P then -p: rejected
	char *k[] = { A("trace"), A("-p"), A("1"), A("-P"), A("pkg") };
	assert(trace_parse_args(5, k, &t) < 0);          // -p then -P: rejected too

	// --dump section (GA2 Phase 3): located alongside the other sections
	char *m[] = { A("trace"), A("-P"), A("pkg"), A("--syscalls"), A("-a"),
	              A("--dump"), A("libfoo*"), A("-d"), A("/tmp/out") };
	assert(trace_parse_args(9, m, &t) == 0);
	assert(t.sys_start == 4 && t.sys_end == 5);
	assert(t.dump_start == 6 && t.dump_end == 9);   // "libfoo*","-d","/tmp/out"

	// --dump before --syscalls, empty --dump section
	char *n[] = { A("trace"), A("-P"), A("pkg"), A("--dump"), A("--syscalls"), A("-a") };
	assert(trace_parse_args(6, n, &t) == 0);
	assert(t.dump_start == 4 && t.dump_end == 4);   // empty, stops at --syscalls
	assert(t.sys_start == 5 && t.sys_end == 6);

	// --- trace_build_argv ---
	struct trace_argv v;

	// syscalls, no prefix
	char *s1[] = { A("trace"), A("-a") };
	int na = trace_build_argv(&v, "syscalls", NULL, NULL, s1, 1, 2, NULL);
	assert(na == 2);
	assert(strcmp(v.argv[0], "syscalls") == 0);
	assert(strcmp(v.argv[1], "-a") == 0);
	assert(v.argv[2] == NULL);

	// funcs, with prefix (package now comes from rc, not injected into argv)
	char *s2[] = { A("trace"), A("-e"), A("lib!fn") };
	int trunc = 0;
	int nb = trace_build_argv(&v, "funcs", "run", "funcs.jsonl", s2, 1, 3, &trunc);
	assert(trunc == 0);
	assert(nb == 5);  // engine + -o file + 2 section args
	assert(strcmp(v.argv[0], "funcs") == 0);
	assert(strcmp(v.argv[1], "-o") == 0);
	assert(strcmp(v.argv[2], "run.funcs.jsonl") == 0);
	assert(strcmp(v.argv[3], "-e") == 0 && strcmp(v.argv[4], "lib!fn") == 0);
	assert(v.argv[5] == NULL);

	// empty section (start == end) — only header entries
	int nc = trace_build_argv(&v, "syscalls", NULL, NULL, s1, 2, 2, NULL);
	assert(nc == 1 && strcmp(v.argv[0], "syscalls") == 0 && v.argv[1] == NULL);

	// truncation: fill past 63-arg limit
	char *big[128]; for (int i = 0; i < 128; i++) big[i] = A("x");
	trunc = 0;
	int nd = trace_build_argv(&v, "syscalls", NULL, NULL, big, 0, 128, &trunc);
	assert(trunc == 1);
	assert(nd == 63);         // 1 engine name + 62 section args
	assert(v.argv[63] == NULL);

	printf("trace_args: ok\n");
	return 0;
}
