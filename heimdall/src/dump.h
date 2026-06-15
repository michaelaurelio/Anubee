/* dump.h
 *
 * Reconstruct a loadable ELF from a library's *live* process memory, capturing
 * any in-memory decryption/unpacking a packer or RASP performs after load.
 *
 * The on-disk .so may be encrypted, partially stripped, or deleted after
 * mapping; what is actually executing is the image in the process address
 * space. We read that image out of /proc/<pid>/mem and rebuild it into a file a
 * disassembler can load directly. This is the same job as F8LEFT/SoFixer, done
 * live against /proc instead of against a pre-made dump, and is a superset of
 * it: program-header fixup, inter-segment gap capture, full section-header
 * reconstruction, relative-relocation un-applying (including DT_RELR, which
 * SoFixer does not handle), and .dynamic de-rebasing (which SoFixer omits).
 *
 * aarch64 (ELF64) only — matching the rest of heimdall.
 */
#ifndef HEIMDALL_DUMP_H
#define HEIMDALL_DUMP_H

/* When set, emit only the phdr-fixed raw memory image (no section-header
 * reconstruction, no relocation un-applying) — a fallback for exotic packers
 * whose dynamic info confuses the rebuilder. */
void dump_set_raw(int on);

/* Dump every currently-mapped module of `pid` whose mapped path contains
 * `substr` by reconstructing a loadable ELF from /proc/<pid>/mem into `outdir`.
 * Each distinct module (load base) is dumped once. Returns the number of files
 * written, or -1 if the process maps could not be read. */
int dump_pid_modules(int pid, const char *substr, const char *outdir);

/* Thin, reusable handles onto the same /proc/<pid>/mem reader the dumper uses,
 * for code that needs to read live target memory by virtual address (e.g. the
 * symbolizer walking ART's in-process JIT debug descriptor). proc_mem_open
 * returns a read-only fd (or -1); proc_mem_read reads `len` bytes from `va` page
 * by page, leaving unreadable holes zeroed, and returns the bytes actually read. */
#include <stdint.h>
#include <stddef.h>
int    proc_mem_open(int pid);
size_t proc_mem_read(int memfd, uint64_t va, void *dst, size_t len);

#endif /* HEIMDALL_DUMP_H */
