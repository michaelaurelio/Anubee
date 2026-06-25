// SPDX-License-Identifier: GPL-2.0
// See maps.h.
#include "common/maps.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>

int ares_parse_maps_line(const char *line, struct ares_map_line *out)
{
	char perms[8];
	char path[256] = "";
	out->path[0] = '\0';
	int got = sscanf(line,
	                 "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %*s %*s %255[^\n]",
	                 &out->start, &out->end, perms, &out->off, path);
	if (got < 4)
		return 0;
	out->exec = (perms[2] == 'x');
	// Strip any leading spaces the path field may carry
	const char *p = path;
	while (*p == ' ') p++;
	snprintf(out->path, sizeof(out->path), "%s", p);
	return 1;
}

size_t ares_module_base_idx(const struct ares_map_line *m, size_t hit)
{
	size_t i = hit;
	while (i > 0 && m[i-1].end == m[i].start && !strcmp(m[i-1].path, m[i].path))
		i--;
	return i;
}

void ares_map_files_path(char *buf, size_t sz, int pid, uint64_t start, uint64_t end)
{
	snprintf(buf, sz, "/proc/%d/map_files/%" PRIx64 "-%" PRIx64, pid, start, end);
}
