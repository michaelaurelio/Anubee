/* symbolize.h
 *
 * Backtrace symbolizer: maps a runtime address in a traced process to
 * "libname.so!function+0xdelta" using /proc/<pid>/maps for module ranges/paths
 * and each ELF's .dynsym for function names. Results are cached.
 *
 * This is display-only. The in-kernel syscall filter does not depend on it and
 * stays driven purely by uprobe_mmap/munmap events.
 */
#ifndef SYSCALLS_SYMBOLIZE_H
#define SYSCALLS_SYMBOLIZE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "common/cfi_unwind.h"

/* Resolve `addr` in process `pid` into `out` (e.g. "librasp.so!checkRoot+0x2c",
 * "libc.so+0x7e0b4", or "0x7..." if no module is found). */
void sym_resolve(int pid, unsigned long long addr, char *out, size_t outsz);

/* Pick the pid whose /proc maps and memory should be used for an event's
 * frames. An exec event's stack predates the exec, so it resolves against the
 * parent; every other event resolves against its own pid, alive or dead, and
 * *fb receives the parent to try when that pid never had a snapshot. For a
 * stack snapshot walk, sym_snapshot_pid picks the parent only for exec events.
 * The pid printed in JSON output is always the real one. */
int sym_effective_pid(int pid, unsigned int aux, int *fb);
int sym_snapshot_pid(int pid, unsigned int aux, int *fb);

/* Resolve `addr` against `pid`; when no mapping is found and `pid`'s maps are
 * gone without a retained snapshot, retry against `fb` (the parent). */
void sym_resolve_fb(int pid, int fb, unsigned long long addr, char *out, size_t outsz);

/* Drop cached /proc maps for a pid (e.g. after a large unmap), forcing a reread
 * on the next resolve. Safe to call for unknown pids. */
void sym_flush_pid(int pid);

/* CFI-unwind a frozen stack snapshot across modules. Writes up to `max` return
 * addresses (innermost first, starting at snap->pc) into out_pcs. Returns the
 * count of PCs written. Reads stack bytes only from the frozen snap->snap window;
 * never touches live target memory. If out_sps is non-NULL it receives each
 * frame's SP (the value used to unwind that frame), parallel to out_pcs — the
 * nterp namer needs the terminal frame's SP to locate its managed ArtMethod*. */
struct anubee_stack_snapshot;
int cfi_unwind_snapshot(int pid, const struct anubee_stack_snapshot *snap,
			uint64_t *out_pcs, int max, uint64_t *out_sps,
			struct cfi_step_diag *out_diags);

/* ---- event-sourced maps models (engines > 0) ---------------------------- */

/* Allocate a new engine id (1, 2, ...). Engine 0 is the legacy live path. */
int sym_engine_new(void);

/* Remembered parent tgid for pid, or 0 when unusable. */
int sym_parent_pid(int pid, unsigned int aux);

/* Feed a map event into engine's model of pid. */
void sym_maps_map(int engine, int pid, int ppid, uint64_t seq, uint64_t start, uint64_t end,
		  uint64_t pgoff, uint64_t inode, uint32_t dev, const char *path);

/* Feed an unmap event; ignored when pid has no model. */
void sym_maps_unmap(int engine, int pid, uint64_t seq, uint64_t start, uint64_t end);

/* Resolve addr against pid's model as of seq. */
void sym_resolve_at(int engine, int pid, int ppid, uint64_t seq, unsigned long long addr,
		    char *out, size_t outsz);

/* CFI-unwind a frozen stack snapshot against the model as of seq. */
int cfi_unwind_snapshot_at(int engine, int pid, uint64_t seq,
			   const struct anubee_stack_snapshot *snap, uint64_t *out_pcs, int max,
			   uint64_t *out_sps, struct cfi_step_diag *out_diags);

/* Events may have been lost for engine: reread live maps on the next miss. */
void sym_maps_dirty(int engine);

/* Drop retired lines no open event needs. */
void sym_maps_compact(int engine, uint64_t oldest_open_seq);

/* One teardown line with the maps-model counters. */
void sym_maps_report(FILE *f, const char *tag);

#endif /* SYSCALLS_SYMBOLIZE_H */
