// SPDX-License-Identifier: GPL-2.0
// Private contract shared by the symbolize.c family (symbolize.c, sym_procmaps.c,
// sym_elf.c, sym_jit.c, sym_vdso.c, sym_apk.c). NOT a public API — every symbol
// here is localized at the common.part.o link step. See symbolize.h for the 5
// exported symbols.
#ifndef ANUBEE_SYMBOLIZE_INTERNAL_H
#define ANUBEE_SYMBOLIZE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <elf.h>
#include "common/maps.h"        // struct anubee_map_line
#include "common/cfi_unwind.h"  // struct cfi_section
#include "common/sym_apk.h"     // apk_so_name/apk_list_sos (public; also used by lib.c)

#define MAX_PATH_LEN 256
#define REFRESH_MS   250
#define SYM_SEQ_LIVE UINT64_MAX   // del_seq: still live; as a lookup argument: current state

// ---- shared helper spine (defined in sym_procmaps.c / sym_elf.c) ----------
long long now_ms(void);                                   // sym_procmaps.c
int  pread_all(int fd, void *buf, size_t n, off_t off);   // sym_elf.c
int  open_module_file(const char *path, int pid, uint64_t vstart, uint64_t vend,
                      uint64_t inode, uint32_t dev);       // sym_elf.c
int  elf_exec_load_base(int fd, uint64_t elf_off, uint64_t seg_file_off,
                        uint64_t seg_start, uint64_t *load_base); // sym_elf.c
const char *basename_of(const char *p);                   // sym_elf.c
void display_name(const char *path, char *buf, size_t n); // sym_elf.c

// ---- procmaps (sym_procmaps.c) --------------------------------------------
struct procmaps {
	int pid;
	struct anubee_map_line *m;
	size_t n, cap;
	long long last_read_ms;
	long long last_used_ms;
	int gone;
	int stale;
	int engine;          // 0 = legacy live-only cache; >0 = event-sourced model of that engine
	int seeded;          // model holds a seed (from /proc or a parent copy)
	int dirty;           // events may have been lost; next miss on a live pid rereads
	int forked;          // model came from a fork event (--proc-track)
	int exited;          // leader exit seen (--proc-track)
	uint64_t exit_seq;   // seq of that exit event (--proc-track)
	uint64_t gen;        // bumped when the pid is known to have exited (pid reuse guard)
	uint64_t last_unmap_seq; // seq of the last unmap applied (--proc-track exec reset)
	long long exit_ms;   // when the pid was seen to exit, 0 = not known to have exited
	struct anubee_map_line *r;   // retired lines (del_seq != SYM_SEQ_LIVE), unsorted
	size_t rn, rcap;
};
struct procmaps *pm_get(int pid);
void read_proc_maps(struct procmaps *pm);
struct anubee_map_line *find_mapping(struct procmaps *pm, uint64_t addr);
struct anubee_map_line *find_mapping_refresh(struct procmaps *pm, uint64_t addr);
void module_base(struct procmaps *pm, struct anubee_map_line *hit,
                 uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end);
void module_base_at(struct procmaps *pm, struct anubee_map_line *hit, uint64_t seq,
                    uint64_t *load_base, uint64_t *elf_off, uint64_t *base_end);
// Force a reread of pid's cached maps on next resolve. Used by sym_flush_pid.
void pm_reset_pid(int pid);
// Eviction hook: defined in symbolize.c, called by pm_get on LRU eviction.
void pm_evict_pid(int pid);

// ---- event-sourced maps models (sym_procmaps.c) ---------------------------
struct procmaps *pm_find_e(int engine, int pid);     // find (engine, pid), no /proc read
struct procmaps *pm_alloc_e(int engine, int pid);    // find or allocate a slot, no /proc read
struct procmaps *pm_get_e(int engine, int pid);      // find, else allocate and seed from /proc
struct anubee_map_line *find_mapping_at(struct procmaps *pm, uint64_t addr, uint64_t seq);
struct anubee_map_line *find_mapping_refresh_at(struct procmaps *pm, uint64_t addr, uint64_t seq);
void pm_apply_map(int engine, int pid, uint64_t seq, uint64_t start, uint64_t end,
                  uint64_t pgoff, uint64_t inode, uint32_t dev, const char *path);
void pm_apply_unmap(int engine, int pid, uint64_t seq, uint64_t start, uint64_t end);
void pm_seed_from_parent(int engine, int pid, int ppid, uint64_t seq);
void pm_seed_copy(int dst_engine, int pid, int src_engine, int ppid, uint64_t seq);
void pm_drop_e(int engine, int pid);
void pm_exec_reset(int engine, int pid, uint64_t seq);
void pm_mark_dirty_all(int engine);                  // events may have been lost
void pm_compact(int engine, uint64_t oldest_open_seq); // drop retired lines no event needs
void pm_note_exit(int engine, int pid);              // remember when the pid exited

struct pm_stats {
	unsigned long long seeds, seed_fail, parent_seeds, merges, revives;
	unsigned long long evictions, maps, unmaps;
	size_t models, lines, retired;
};
void pm_stats_get(struct pm_stats *out);             // counts are computed over all slots

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
                          int pid, uint64_t vstart, uint64_t vend,
                          uint64_t inode, uint32_t dev);
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
                            int pid, uint64_t vstart, uint64_t vend,
                            uint64_t inode, uint32_t dev);

// ---- resolver hooks (each subsystem file) ---------------------------------
int  jit_resolve(int pid, uint64_t addr, char *out, size_t outsz);   // sym_jit.c
void jit_reset_pid(int pid);                                          // sym_jit.c
int  vdso_resolve(int pid, uint64_t addr, uint64_t base, uint64_t end,
                  char *out, size_t outsz);                           // sym_vdso.c
void vdso_reset_pid(int pid);                                         // sym_vdso.c
// apk_so_name/apk_list_sos: see common/sym_apk.h (public, included above).

#endif /* ANUBEE_SYMBOLIZE_INTERNAL_H */
