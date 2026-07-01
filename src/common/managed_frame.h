/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARES_MANAGED_FRAME_H
#define ARES_MANAGED_FRAME_H

#include <stddef.h>
#include <stdint.h>

struct ares_stack_snapshot;   /* full def in common/stack_snapshot.h */
struct jbuf;                  /* full def in common/emit.h */
struct cfi_step_diag;         /* full def in common/cfi_unwind.h (optional debug) */

/* ---- PURE (managed_frame.c, host-testable) ------------------------------ */

/* True if `sym` is one of ART's interpreter entrypoints (a Java method is being
 * interpreted; no native frame names it). Shared so syscalls.c and symbolize.c
 * use one definition. */
int ares_is_interp_frame(const char *sym);

/* Build a JSON-array fragment of managed method names from `n` resolved frame
 * symbols (innermost-first). A frame is managed iff its symbol contains
 * ".oat!" / ".odex!" / ".vdex!"; the emitted name is the text after the last
 * '!'. Any non-empty `nterp_names` (the interpreted chain, innermost-first) are
 * appended after the native-resolved managed frames. Writes a NUL-terminated
 * fragment (e.g. ["pkg.A.b","pkg.C.d"]) into out (<= cap). Returns the number
 * of methods; 0 => out is left untouched. */
int ares_managed_chain_build(const char *const *syms, int n,
                             const char *const *nterp_names, int nterp_n,
                             char *out, size_t cap);

/* Bounded, mutex-guarded stack_id -> fragment cache.
 * put() stores frag (must fit within JC_FRAG bytes including NUL) for stack_id.
 * get() copies the cached fragment into out (NUL-terminated, <= cap) while
 *   holding the lock; returns 1 if found (out written), 0 on miss or cap-too-small
 *   (out untouched either way).
 * reset() clears all slots (test / teardown only). */
void ares_jcache_put(uint64_t stack_id, const char *frag);
int  ares_jcache_get(uint64_t stack_id, char *out, size_t cap);
void ares_jcache_reset(void);

/* ---- IMPURE (symbolize.c; declared here, device-tested) ----------------- */

/* Resolve the managed chain for an already-CFI-walked snapshot. pcs/sps/n come
 * from cfi_unwind_snapshot(). Resolves each PC, detects an nterp terminal and
 * names it, then calls ares_managed_chain_build. Returns method count. */
int ares_managed_chain(int pid, const struct ares_stack_snapshot *s,
                       const uint64_t *pcs, const uint64_t *sps, int n,
                       char *out, size_t cap);

/* Serialize a {"type":"cfi_stack",...} record (kind tags + nterp terminal
 * append) into j, from an already-walked pcs/sps/n. The single cfi_stack
 * serializer for BOTH engines. If diags != NULL, per-frame ARES_CFI_DEBUG fields
 * are emitted (parallel to pcs, length n); funcs passes NULL, syscalls passes its
 * diag array when ARES_CFI_DEBUG is set. */
void ares_emit_cfi_stack_json(struct jbuf *j, int pid,
                              const struct ares_stack_snapshot *s,
                              const uint64_t *pcs, const uint64_t *sps, int n,
                              const struct cfi_step_diag *diags);

#endif /* ARES_MANAGED_FRAME_H */
