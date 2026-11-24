// SPDX-License-Identifier: GPL-2.0
// Pure helpers for the fileless-detect analyzer (src/modules/fileless_detect.c):
// locating the mapping that holds an address in a /proc/<pid>/maps text and
// the name the kernel gives it, telling ART's own JIT regions apart by that
// name, and classifying a region's first bytes. libc only -- host-testable.
#ifndef __ANUBEE_FILELESS_DETECT_PARSE_H
#define __ANUBEE_FILELESS_DETECT_PARSE_H

#include <stddef.h>

// fileless_detect_event.kind
enum fl_kind {
    FL_KIND_ANON_MMAP   = 1,   // anonymous mapping created executable
    FL_KIND_MPROTECT_EXEC = 2, // anonymous/shared/memfd memory made executable later
    FL_KIND_MEMFD_EXEC  = 3,   // memfd file mapped executable (incl. exec from memfd)
};
const char *fl_kind_name(int kind);   // "anon_exec_mmap" "mprotect_exec" "memfd_exec", else "unknown"

// Find the maps line whose [start, end) holds addr. Returns 1 and fills the
// outputs (perms: 5 bytes incl. NUL; name: "[anon:x]"/"[anon_shmem:x]" reduced
// to "x", a file path kept as printed, "" when unnamed), else 0.
int fl_maps_region(const char *maps, unsigned long addr, unsigned long *start,
                   unsigned long *end, char perms[8], char *name, size_t cap);

// ART's own executable memory: anonymous regions it names "dalvik-*" and the
// memfd-backed JIT caches "jit-cache" / "jit-zygote-cache" (in either the
// "memfd:x" or maps "/memfd:x (deleted)" form).
int fl_name_is_art(const char *name);

// "elf" (ELF header), "zero" (all zero bytes), "data" (anything else), or
// NULL when n == 0 (nothing could be read).
const char *fl_content_of(const unsigned char *b, size_t n);

#endif /* __ANUBEE_FILELESS_DETECT_PARSE_H */
