/* rebuild.h
 *
 * Reconstruct a loadable ELF from a library's *live* process memory, capturing
 * any in-memory decryption/unpacking a packer or RASP performs after load.
 * Read out of /proc/<pid>/mem and rebuilt into a file a disassembler can load:
 * program-header fixup, inter-segment gap capture, full section-header
 * reconstruction, relative-relocation un-applying (incl. DT_RELR), and .dynamic
 * de-rebasing. aarch64 (ELF64) only.
 */
#ifndef ARES_DUMP_REBUILD_H
#define ARES_DUMP_REBUILD_H

/* When set, emit only the phdr-fixed raw memory image (no section-header
 * reconstruction, no relocation un-applying) — a fallback for exotic packers
 * whose dynamic info confuses the rebuilder. */
void dump_set_raw(int on);

/* Dump every currently-mapped module of `pid` whose mapped path matches
 * `pattern` (glob on basename, else substring of full path) into `outdir`. Each
 * distinct module (load base) is dumped once. Returns the number of files
 * written, or -1 if the process maps could not be read. (Dump-on-exit path.) */
int dump_pid_modules(int pid, const char *pattern, const char *outdir);

/* Dump the single module whose load range contains virtual address `addr` (the
 * start of a just-mapped executable segment) into `outdir`, labelling the output
 * with `name`. Returns 0 on success, -1 on failure. (Dump-on-map path.) */
int dump_one_at(int pid, unsigned long long addr, const char *name, const char *outdir);

/* Does `path` match `pattern`? Glob (fnmatch on basename, " (deleted)" stripped)
 * when `pattern` has glob metacharacters, else substring-of-full-path. */
int dump_name_matches(const char *pattern, const char *path);

#endif /* ARES_DUMP_REBUILD_H */
