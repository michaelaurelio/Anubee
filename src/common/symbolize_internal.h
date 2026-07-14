// SPDX-License-Identifier: GPL-2.0
// Private contract shared by the symbolize.c family (symbolize.c, sym_procmaps.c,
// sym_elf.c, sym_jit.c, sym_vdso.c, sym_apk.c). NOT a public API — every symbol
// here is localized at the common.part.o link step. See symbolize.h for the 5
// exported symbols.
#ifndef ARES_SYMBOLIZE_INTERNAL_H
#define ARES_SYMBOLIZE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <elf.h>
#include "common/maps.h"        // struct ares_map_line
#include "common/cfi_unwind.h"  // struct cfi_section
#include "common/sym_apk.h"     // apk_so_name/apk_list_sos (public; also used by lib.c)

#define MAX_PATH_LEN 256
#define REFRESH_MS   250

// ---- shared helper spine (defined in sym_procmaps.c / sym_elf.c) ----------
long long now_ms(void);                                   // sym_procmaps.c
int  pread_all(int fd, void *buf, size_t n, off_t off);   // sym_elf.c
int  open_module_file(const char *path, int pid, uint64_t vstart, uint64_t vend); // sym_elf.c
const char *basename_of(const char *p);                   // sym_elf.c
void display_name(const char *path, char *buf, size_t n); // sym_elf.c

// ---- procmaps (sym_procmaps.c) --------------------------------------------
struct procmaps {
	int pid;
	struct ares_map_line *m;
	size_t n, cap;
	long long last_read_ms;
	long long last_used_ms;
	int gone;
};
struct procmaps *pm_get(int pid);
void read_proc_maps(struct procmaps *pm);
struct ares_map_line *find_mapping(struct procmaps *pm, uint64_t addr);
struct ares_map_line *find_mapping_refresh(struct procmaps *pm, uint64_t addr);
void module_base(struct procmaps *pm, struct ares_map_line *hit,
                 uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end);
// Force a reread of pid's cached maps on next resolve. Used by sym_flush_pid.
void pm_reset_pid(int pid);
// Eviction hook: defined in symbolize.c, called by pm_get on LRU eviction.
void pm_evict_pid(int pid);

// ---- ELF symbol tables (sym_elf.c) — reused by sym_vdso.c -----------------
struct sym { uint64_t value, size; uint32_t name_off; };
struct dynsym {
	char path[MAX_PATH_LEN];
	uint64_t elf_off;
	char *str; size_t strn; size_t strcap;
	struct sym *s; size_t ns;
	int ok;
};
void add_symbols(struct dynsym *ds, const void *symbuf, size_t symbytes,
                 size_t entsize, const char *str, size_t strn);
void ingest_fd_section(struct dynsym *ds, int fd, uint64_t elf_off,
                       const Elf64_Shdr *symsec, const Elf64_Shdr *strsec);
void dynsym_finalize(struct dynsym *ds);
struct dynsym *dynsym_get(const char *path, uint64_t elf_off,
                          int pid, uint64_t vstart, uint64_t vend);
const char *sym_lookup(struct dynsym *ds, uint64_t vaddr, uint64_t *delta);
// Bounds-check an ELF section-header table (e_shnum entries of e_shentsize
// bytes starting at e_shoff) against a buffer of length `len`. Overflow-safe:
// e_shoff/e_shnum/e_shentsize are untrusted (attacker-controlled via a
// crafted ELF or .gnu_debugdata) and must never be added directly to a
// pointer without first checking they can't wrap mod 2^64. Returns 1 if the
// whole table fits in-bounds, 0 otherwise.
int elf_shtab_in_bounds(uint64_t e_shoff, uint32_t e_shnum, uint32_t e_shentsize, size_t len);

// ---- per-module CFI cache (sym_elf.c) -------------------------------------
struct cfi_section *cfi_get(const char *path, uint64_t elf_off, uint64_t load_base,
                            int pid, uint64_t vstart, uint64_t vend);

// ---- resolver hooks (each subsystem file) ---------------------------------
int  jit_resolve(int pid, uint64_t addr, char *out, size_t outsz);   // sym_jit.c
void jit_reset_pid(int pid);                                          // sym_jit.c
int  vdso_resolve(int pid, uint64_t addr, uint64_t base, uint64_t end,
                  char *out, size_t outsz);                           // sym_vdso.c
void vdso_reset_pid(int pid);                                         // sym_vdso.c
// apk_so_name/apk_list_sos: see common/sym_apk.h (public, included above).

#endif /* ARES_SYMBOLIZE_INTERNAL_H */
