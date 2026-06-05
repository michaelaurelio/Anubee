/* symbolize.h
 *
 * Backtrace symbolizer: maps a runtime address in a traced process to
 * "libname.so!function+0xdelta" using /proc/<pid>/maps for module ranges/paths
 * and each ELF's .dynsym for function names. Results are cached.
 *
 * This is display-only. The in-kernel syscall filter does not depend on it and
 * stays driven purely by uprobe_mmap/munmap events.
 */
#ifndef HEIMDALL_SYMBOLIZE_H
#define HEIMDALL_SYMBOLIZE_H

#include <stddef.h>

/* Resolve `addr` in process `pid` into `out` (e.g. "librasp.so!checkRoot+0x2c",
 * "libc.so+0x7e0b4", or "0x7..." if no module is found). */
void sym_resolve(int pid, unsigned long long addr, char *out, size_t outsz);

/* Drop cached /proc maps for a pid (e.g. after a large unmap), forcing a reread
 * on the next resolve. Safe to call for unknown pids. */
void sym_flush_pid(int pid);

#endif /* HEIMDALL_SYMBOLIZE_H */
