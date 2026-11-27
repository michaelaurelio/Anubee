// SPDX-License-Identifier: GPL-2.0
// Shared /proc/<pid>/maps line parser. Pure: no I/O, no globals, no allocation.
// Include this wherever you open /proc/<pid>/maps and loop over lines.
#ifndef __ANUBEE_MAPS_H
#define __ANUBEE_MAPS_H

#include <stddef.h>
#include <stdint.h>

struct anubee_map_line {
	uint64_t start, end, off;
	int exec;           // 1 if 'x' in perms, 0 otherwise
	char path[256];     // empty string for anonymous/special mappings
	uint64_t inode;     // inode number from the maps line, 0 for anonymous
	uint32_t dev;       // device, kernel internal encoding (major << 20) | minor
	uint64_t id;        // process-unique line id assigned by the maps model; 0 = none
	uint64_t add_seq;   // stream sequence from which the line is valid
	uint64_t del_seq;   // stream sequence at which it was retired (SYM_SEQ_LIVE = still live)
	uint64_t xbase;     // cached exec-only load base (valid when xstate == 1)
	uint64_t xelf;      // cached ELF start offset for xbase
	int xstate;         // 0 not tried, 1 derived, -1 derivation failed
};

// Parse one /proc/<pid>/maps line into *out.
// Returns 1 if the line is usable (start/end/perms/offset all present), 0 to skip.
int anubee_parse_maps_line(const char *line, struct anubee_map_line *out);

// Walk back over an address-sorted anubee_map_line array to find the load-base
// index: the lowest index in the same-path run reachable by strictly-decreasing
// file offsets, skipping filler mappings (anonymous or "[...]"-bracket pseudo-
// mappings such as the Android 16 KB-page "[page size compat]" guard) that may
// separate one ELF's PT_LOAD segments. An offset reset stops the walk, separating
// a distinct re-load of the same path.
// Requires m[] to be address-sorted (as /proc/<pid>/maps always is).
size_t anubee_module_base_idx(const struct anubee_map_line *m, size_t hit);

// Format /proc/<pid>/map_files/<start>-<end> into buf[sz].
void anubee_map_files_path(char *buf, size_t sz, int pid,
                         uint64_t start, uint64_t end);

#endif /* __ANUBEE_MAPS_H */
