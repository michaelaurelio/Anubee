// SPDX-License-Identifier: GPL-2.0
// Generic /proc/<pid>/mem reader. Shared by the dump engine (ELF image capture)
// and the syscalls symbolizer (ART in-process JIT debug-descriptor walk), so the
// page-by-page reader lives once. Linked via build/common.part.o (COMMON_API).
#ifndef ARES_COMMON_PROC_MEM_H
#define ARES_COMMON_PROC_MEM_H

#include <stdint.h>
#include <stddef.h>

// Open /proc/<pid>/mem read-only (O_CLOEXEC). Returns the fd, or -1.
int proc_mem_open(int pid);

// Read `len` bytes from virtual address `va`, page by page. Unreadable pages
// (guard gaps) are skipped without error, leaving those destination bytes
// untouched — callers that need holes zeroed pre-zero the buffer (e.g. calloc).
// Returns the number of bytes actually read out of memory.
size_t proc_mem_read(int memfd, uint64_t va, void *dst, size_t len);

#endif /* ARES_COMMON_PROC_MEM_H */
