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
#include "common/cfi_unwind.h"

/* Resolve `addr` in process `pid` into `out` (e.g. "librasp.so!checkRoot+0x2c",
 * "libc.so+0x7e0b4", or "0x7..." if no module is found). */
void sym_resolve(int pid, unsigned long long addr, char *out, size_t outsz);

/* Drop cached /proc maps for a pid (e.g. after a large unmap), forcing a reread
 * on the next resolve. Safe to call for unknown pids. */
void sym_flush_pid(int pid);

/* CFI-unwind a frozen stack snapshot across modules. Writes up to `max` return
 * addresses (innermost first, starting at snap->pc) into out_pcs. Returns the
 * count of PCs written. Reads stack bytes only from the frozen snap->snap window;
 * never touches live target memory. If out_sps is non-NULL it receives each
 * frame's SP (the value used to unwind that frame), parallel to out_pcs — the
 * nterp namer needs the terminal frame's SP to locate its managed ArtMethod*. */
struct ares_stack_snapshot;
int cfi_unwind_snapshot(int pid, const struct ares_stack_snapshot *snap,
			uint64_t *out_pcs, int max, uint64_t *out_sps,
			struct cfi_step_diag *out_diags);

#endif /* SYSCALLS_SYMBOLIZE_H */
