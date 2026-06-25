// SPDX-License-Identifier: GPL-2.0
// Shared /proc/<pid>/maps line parser. Pure: no I/O, no globals, no allocation.
// Include this wherever you open /proc/<pid>/maps and loop over lines.
#ifndef __ARES_MAPS_H
#define __ARES_MAPS_H

#include <stddef.h>
#include <stdint.h>

struct ares_map_line {
	uint64_t start, end, off;
	int exec;           // 1 if 'x' in perms, 0 otherwise
	char path[256];     // empty string for anonymous/special mappings
};

// Parse one /proc/<pid>/maps line into *out.
// Returns 1 if the line is usable (start/end/perms/offset all present), 0 to skip.
int ares_parse_maps_line(const char *line, struct ares_map_line *out);

// Walk back over an address-sorted ares_map_line array to find the load-base
// index: the lowest index in the contiguous same-path run containing m[hit].
// Requires m[] to be address-sorted (as /proc/<pid>/maps always is).
size_t ares_module_base_idx(const struct ares_map_line *m, size_t hit);

// Format /proc/<pid>/map_files/<start>-<end> into buf[sz].
void ares_map_files_path(char *buf, size_t sz, int pid,
                         uint64_t start, uint64_t end);

#endif /* __ARES_MAPS_H */
