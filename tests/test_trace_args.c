// SPDX-License-Identifier: GPL-2.0
// Host check for the `ares trace` arg-section splitter.
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

	// errors / help
	char *d[] = { A("trace"), A("-P") };
	assert(trace_parse_args(2, d, &t) < 0);          // -P missing value
	char *e[] = { A("trace"), A("--help") };
	assert(trace_parse_args(2, e, &t) == 1);
	char *f[] = { A("trace"), A("bogus") };
	assert(trace_parse_args(2, f, &t) < 0);          // unexpected token

	printf("trace_args: ok\n");
	return 0;
}
