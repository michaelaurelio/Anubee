// SPDX-License-Identifier: GPL-2.0
// See maps.h.
#include "common/maps.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>

int anubee_parse_maps_line(const char *line, struct anubee_map_line *out)
{
	char perms[8];
	char path[256] = "";
	unsigned int major = 0, minor = 0;
	uint64_t inode = 0;
	out->path[0] = '\0';
	out->dev = 0;
	out->inode = 0;
	out->id = 0;
	out->add_seq = 0;
	out->del_seq = 0;
	out->xbase = 0;
	out->xelf = 0;
	out->xstate = 0;
	int got = sscanf(line,
	                 "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %x:%x %" SCNu64 " %255[^\n]",
	                 &out->start, &out->end, perms, &out->off,
	                 &major, &minor, &inode, path);
	if (got < 4)
		return 0;
	if (got >= 6)
		out->dev = ((uint32_t)major << 20) | (uint32_t)minor;
	if (got >= 7)
		out->inode = inode;
	out->exec = (perms[2] == 'x');
	// Strip any leading spaces the path field may carry
	const char *p = path;
	while (*p == ' ') p++;
	snprintf(out->path, sizeof(out->path), "%s", p);
	return 1;
}

// A mapping that is not a named file: anonymous (empty path) or a kernel
// pseudo-mapping ("[page size compat]", "[anon:...]", "[stack]", ...). PT_LOAD
// segments of one ELF can be separated by these — notably the Android 16 KB-page
// "[page size compat]" guard between the RO and exec segments.
static int anubee_is_filler_map(const struct anubee_map_line *m)
{
	return m->path[0] == '\0' || m->path[0] == '[';
}

size_t anubee_module_base_idx(const struct anubee_map_line *m, size_t hit)
{
	size_t i = hit;
	while (i > 0) {
		size_t j = i - 1;
		while (j > 0 && anubee_is_filler_map(&m[j]))
			j--;
		if (!strcmp(m[j].path, m[i].path) && m[j].off < m[i].off)
			i = j;
		else
			break;
	}
	return i;
}

void anubee_map_files_path(char *buf, size_t sz, int pid, uint64_t start, uint64_t end)
{
	snprintf(buf, sz, "/proc/%d/map_files/%" PRIx64 "-%" PRIx64, pid, start, end);
}
