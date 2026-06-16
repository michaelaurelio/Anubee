// SPDX-License-Identifier: GPL-2.0
// proc_mem.c — see proc_mem.h.
#include "common/proc_mem.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define PROC_MEM_PAGE 0x1000ull

int proc_mem_open(int pid)
{
	char mp[64];
	snprintf(mp, sizeof(mp), "/proc/%d/mem", pid);
	return open(mp, O_RDONLY | O_CLOEXEC);
}

size_t proc_mem_read(int memfd, uint64_t va, void *dst, size_t len)
{
	unsigned char *d = (unsigned char *)dst;
	uint64_t off = 0;
	size_t got = 0;
	while (off < len) {
		uint64_t chunk = PROC_MEM_PAGE - ((va + off) & (PROC_MEM_PAGE - 1));
		if (chunk > len - off)
			chunk = len - off;
		ssize_t r = pread(memfd, d + off, chunk, (off_t)(va + off));
		if (r <= 0) {
			off += chunk;          // hole: skip the page, leave dst as-is
			continue;
		}
		got += (size_t)r;
		off += (size_t)r;
	}
	return got;
}
