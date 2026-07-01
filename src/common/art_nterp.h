// SPDX-License-Identifier: GPL-2.0
// art_nterp.h — name the interpreted (nterp) Java method at a CFI terminal that
// lands in libart's nterp fast interpreter.
//
// The native CFI unwind crosses into AOT-compiled Java but dies one frame short at
// libart!nterp_helper: the managed method above it is an ART nterp frame, not a
// native frame. ART keeps the current ArtMethod* at the base of that nterp frame
// (offset 0 from its SP), which sits on the captured stack just above nterp_helper's
// SP. We read that ArtMethod* from the frozen snapshot bytes and chase ART structs
// LIVE via /proc/<pid>/mem to (DexFile, dex_method_index) -> "pkg.Class.method".
//
// Firewall: reads only (snapshot bytes + /proc/<pid>/mem); writes nothing, attaches
// nothing. ART-version-gated: an unrecognized ART build resolves nothing (the caller
// keeps today's bare-offset terminal). Offsets are version-coupled — see
// docs/superpowers/research/2026-07-01-nterp-offsets-spike-findings.md.
#ifndef ARES_COMMON_ART_NTERP_H
#define ARES_COMMON_ART_NTERP_H

#include <stdint.h>
#include <stddef.h>

struct ares_stack_snapshot;   // full definition in common/stack_snapshot.h

// Resolve the nterp-interpreted Java method whose managed frame sits at/above
// `nterp_sp` (the recovered SP of the libart nterp_helper terminal frame). Writes
// "pkg.Class.method" to out and returns 1 on success; returns 0 on unknown ART
// version, faulting read, or no resolvable method in the scan window.
int nterp_name(int pid, const struct ares_stack_snapshot *snap, uint64_t nterp_sp,
               char *out, size_t outsz);

// ---- host-test seam ------------------------------------------------------------
// Reads `len` bytes of target memory at `va` into dst; returns bytes read (a short
// read => failure for the fixed-width helpers). The production reader wraps
// proc_mem_read; tests inject a synthetic address space.
typedef size_t (*art_reader)(void *ctx, uint64_t va, void *dst, size_t len);

// Chase one candidate ArtMethod* to a method name using `rd`. Returns 1 on success.
// Exposed for host testing (test_art_nterp.c); production goes through nterp_name.
int art_method_resolve(art_reader rd, void *rc, uint64_t artmethod,
                       char *out, size_t outsz);

// Chase one ArtMethod* to its DEX (method_idx, image begin_, code_item map) WITHOUT
// naming it. Exposed so the ShadowFrame walk can corroborate a live dex_pc against the
// method's own bytecode. Returns 1 on a fully-valid chain. `begin_out`/`map_out` may be NULL.
struct dex_method_map;   // opaque (full def in dex.h)
int art_method_chase(art_reader rd, void *rc, uint64_t artmethod,
                     uint32_t *midx_out, uint64_t *begin_out,
                     struct dex_method_map **map_out);

// Core locator, exposed for host testing. Scans stack slots upward from nterp_sp
// (bytes in `stack`, addresses `stack_base..stack_base+stack_len`) for the managed
// frame's ArtMethod*, corroborating each candidate against a live dex_pc for the
// same method. Writes "pkg.Class.method+0x<dexpc>" (corroborated) or bare
// "pkg.Class.method" (uncorroborated fallback) and returns 1; returns 0 on no
// resolvable candidate. Chases ArtMethod structs via rd; reads dex_pc from `stack`.
int nterp_pick(art_reader rd, void *rc, const uint8_t *stack, uint64_t stack_base,
               size_t stack_len, uint64_t nterp_sp, char *out, size_t outsz);

// Name the FULL interpreted call chain above the nterp terminal at `nterp_sp`.
// Scans the frozen snapshot upward, emitting each dex_pc-corroborated method
// (innermost-first, "pkg.Class.method+0x<dexpc>") into out[0..return). Returns the
// count. Superset of nterp_name; uncorroborated frames are dropped.
int nterp_chain(int pid, const struct ares_stack_snapshot *snap, uint64_t nterp_sp,
                char out[][256], int max_frames);
int nterp_chain_pick(art_reader rd, void *rc, const uint8_t *stack, uint64_t stack_base,
                     size_t stack_len, uint64_t nterp_sp, char out[][256], int max_frames);

// Drop the cached DexFile image maps (host tests reset state between cases).
void art_nterp_cache_reset(void);

#endif /* ARES_COMMON_ART_NTERP_H */
