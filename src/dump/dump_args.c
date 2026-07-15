// SPDX-License-Identifier: GPL-2.0
// dump_args.c - see dump_args.h.
#include "dump/dump_args.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

const char *dump_args_check(const struct dump_trigger *t)
{
	if (t->ntgt > 0 && t->has_pkg)
		return "specify exactly one of -p or -P";
	if (!t->ntgt && !t->has_pkg)
		return "specify -P PACKAGE or -p PID[,PID...]";
	if (t->npat == 0 && t->nbase == 0)
		return "at least one library pattern (-l) or --base ADDR is required";
	if (t->now && t->has_pkg)
		return "--now requires -p PID (with -P the app has not launched yet)";
	if (t->now && t->on_map)
		return "--now and --on-map are mutually exclusive triggers";
	if (t->check && !t->now)
		return "--check requires --now";
	return NULL;
}

int dump_parse_base(const char *arg, unsigned long long *out)
{
	if (!arg || !isdigit((unsigned char)arg[0]))
		return -1;   /* rejects "", "-1", "+1", " 0x1", "abc" up front */

	char *end = NULL;
	errno = 0;
	unsigned long long v = strtoull(arg, &end, 0);
	if (!end || *end || end == arg || errno == ERANGE)
		return -1;

	*out = v;
	return 0;
}
