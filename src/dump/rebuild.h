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

struct ares_sink;  /* common/emit.h */

/* When set, emit only the phdr-fixed raw memory image (no section-header
 * reconstruction, no relocation un-applying) — a fallback for exotic packers
 * whose dynamic info confuses the rebuilder. */
void dump_set_raw(int on);

/* A module selector: patterns (by name) OR exact load bases. The two are OR'd,
 * never AND'd. A base selector ignores the path entirely, which is the point:
 * it selects the module actually observed at that address, so a per-run
 * randomized name, a rename-after-dlopen, or a " (deleted)" path cannot defeat
 * it. Either side may be empty (NULL/0); an all-empty selector matches nothing
 * (dump_args_check rejects that combination before it can reach here). */
struct dump_sel {
	const char *const *pats;             /* -l patterns, or NULL */
	int                npat;
	int               *hit;              /* optional npat-element hit tracker */
	const unsigned long long *bases;     /* --base addresses, or NULL */
	int                nbase;
};

/* Does the module at `path`, loaded at `base`, match the selector? */
int dump_sel_matches(const struct dump_sel *sel, const char *path,
                     unsigned long long base);

/* Invoked once per distinct module of `pid` matching the selector. `memfd` is an
 * already-open /proc/<pid>/mem (the walker owns it; do not close it). Return 0
 * on success, -1 on failure - the walker counts successes. Set *covered_end to
 * the module's end vaddr when it is known, so the walker skips later segments of
 * the same module; leave it alone when unknown. */
typedef int (*dump_mod_fn)(int pid, int memfd, unsigned long long base,
                           const char *path, void *ctx,
                           unsigned long long *covered_end);

/* Walk `pid`'s /proc/<pid>/maps and invoke `fn` once per distinct module
 * matching `sel`, deduplicating by load base and by the covered ranges callbacks
 * report. Returns the number of `fn` calls that returned 0, or -1 if the maps or
 * /proc/<pid>/mem could not be read. Owns the maps buffer and the mem fd.
 *
 * Extracted so the dump and check paths share one walk: the dedup rules here are
 * subtle (see the coverage-range comment at the call site) and are worth having
 * in exactly one place. */
int dump_walk_pid_modules(int pid, const struct dump_sel *sel,
                          dump_mod_fn fn, void *ctx);

/* Selector-driven form of dump_pid_modules (which is a thin wrapper over this
 * with bases empty). Same return contract. */
int dump_pid_modules_sel(int pid, const struct dump_sel *sel,
                         const char *outdir, struct ares_sink *sink);

/* Dump every currently-mapped module of `pid` whose mapped path matches ANY of
 * `pats` (glob on basename, else substring of full path) into `outdir`. Each
 * distinct module (load base) is dumped once. Returns the number of files
 * written, or -1 if the process maps could not be read. (Dump-on-exit path.)
 * sink: SYM1 Phase 3 machine channel — a {"type":"dump",...} manifest record is
 * emitted per module written when sink is non-NULL and open (sink->f); pass
 * NULL when -o wasn't given.
 * hit: optional per-pattern "did this pattern match anything" tracking array
 * (must have npat elements if non-NULL); see dump_name_matches_any_track.
 * Pass NULL if the caller doesn't need it. */
int dump_pid_modules(int pid, const char *const *pats, int npat,
                     const char *outdir, struct ares_sink *sink, int *hit);

/* Dump the single module whose load range contains virtual address `addr` (the
 * start of a just-mapped executable segment) into `outdir`, labelling the output
 * with `name`. Returns 0 on success, -1 on failure. (Dump-on-map path.)
 * sink: see dump_pid_modules above. */
int dump_one_at(int pid, unsigned long long addr, const char *name, const char *outdir, struct ares_sink *sink);

/* Does `path` match `pattern`? Glob (fnmatch on basename, " (deleted)" stripped)
 * when `pattern` has glob metacharacters, else substring-of-full-path. */
int dump_name_matches(const char *pattern, const char *path);

/* Does `path` match ANY of the npat patterns? (OR of dump_name_matches.) */
int dump_name_matches_any(const char *const *pats, int npat, const char *path);

/* Like dump_name_matches_any, but also records into hit[i] (if hit != NULL,
 * must have npat elements) whether pats[i] matched -- lets callers track
 * "this pattern never matched anything" across a run without duplicating
 * the match loop. */
int dump_name_matches_any_track(const char *const *pats, int npat, const char *path, int *hit);

#endif /* ARES_DUMP_REBUILD_H */
