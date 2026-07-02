// SPDX-License-Identifier: GPL-2.0
// art_nterp.c — see art_nterp.h. Names interpreted (nterp) Java frames by chasing
// ART runtime structs out-of-process. All reads, no writes (firewall-clean).
//
// Offset table (ART apex 370549100, Android 15, arm64) — verified against AOSP
// android15-release; see the spike findings doc. References are 32-bit compressed:
// decompress = zero-extend (no heap base; poisoning is off on release builds).
#include "common/art_nterp.h"
#include "common/art_buildid.h"
#include "common/dex.h"
#include "common/proc_mem.h"

#include <linux/types.h>          /* __u32/__u64 for stack_snapshot.h */
#include "common/stack_snapshot.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

// Strip the Android top-byte pointer tag (TBI / MTE) from a native pointer before
// dereferencing via /proc/<pid>/mem, which rejects tagged addresses. Compressed
// (32-bit) references never carry a tag; only full 64-bit native pointers do.
#define ART_PTR_UNTAG(p) ((uint64_t)(p) & 0x00FFFFFFFFFFFFFFULL)

// How far above nterp_helper's SP to scan for the managed frame's ArtMethod*.
// nterp's native helper frames vary in size, so the managed frame base can sit a
// few KB up. Corroboration (below) filters false positives structurally, so this
// window can be generous; cost is deduped per-stack. Tune on-device if terminals
// still miss.
#define NTERP_SCAN_WIN  8192
// How far ABOVE a candidate ArtMethod* slot to search for its live dex_pc (the
// nterp managed frame stores dex_pc above the frame base). Bounded and small.
#define NTERP_CORROB_SPAN  512

// ---- fixed-width readers over the injected reader ------------------------------
static int rd_u32(art_reader rd, void *rc, uint64_t va, uint32_t *out)
{
    return rd(rc, va, out, 4) == 4;
}
static int rd_u64(art_reader rd, void *rc, uint64_t va, uint64_t *out)
{
    return rd(rc, va, out, 8) == 8;
}

// ---- DexFile image cache (keyed by DexFile.begin_) ------------------------------
// nterp_name runs once per *distinct* stack (deduped by the caller), but many
// stacks share a DexFile, so cache the built maps. The mutex guards the shared array
// so a future multi-worker drain stays consistent. A cached map pointer is handed to
// the caller and dereferenced after the lock is dropped, so cached maps are
// IMMORTAL: once stored they are never freed (eviction drops the slot but leaks the
// map) — that keeps a returned pointer valid even if a second worker evicts
// concurrently. The set of loaded DexFiles is small (tens), so the FIFO cap is rarely
// hit and the leak is bounded. art_nterp_cache_reset (host-test teardown only) frees
// everything and must not run while any resolve is in flight.
struct dex_cache_ent { uint64_t begin; struct dex_method_map *map; };
static struct dex_cache_ent g_dexc[64];
static size_t g_ndexc;
static pthread_mutex_t g_dexc_lock = PTHREAD_MUTEX_INITIALIZER;

void art_nterp_cache_reset(void)
{
    pthread_mutex_lock(&g_dexc_lock);
    for (size_t i = 0; i < g_ndexc; i++)
        dex_map_free(g_dexc[i].map);
    g_ndexc = 0;
    pthread_mutex_unlock(&g_dexc_lock);
}

// Read the DexFile image [begin, begin+size) via rd, build a method map, cache it.
// Returns the (cached) map or NULL.
static struct dex_method_map *dexmap_get(art_reader rd, void *rc,
                                         uint64_t begin, uint64_t size)
{
    pthread_mutex_lock(&g_dexc_lock);
    for (size_t i = 0; i < g_ndexc; i++)
        if (g_dexc[i].begin == begin) {
            struct dex_method_map *m = g_dexc[i].map;
            pthread_mutex_unlock(&g_dexc_lock);
            return m;
        }
    pthread_mutex_unlock(&g_dexc_lock);

    uint8_t *img = malloc((size_t)size);
    if (!img)
        return NULL;
    if (rd(rc, begin, img, (size_t)size) != (size_t)size) {
        free(img);
        return NULL;
    }
    struct dex_method_map *m = dex_map_build(img, (size_t)size);
    free(img);                       // dex_map_build keeps its own copy
    if (!m)
        return NULL;

    const size_t cap = sizeof(g_dexc) / sizeof(g_dexc[0]);
    pthread_mutex_lock(&g_dexc_lock);
    // A racing thread may have inserted the same begin while we built ours; re-check.
    for (size_t i = 0; i < g_ndexc; i++)
        if (g_dexc[i].begin == begin) {
            struct dex_method_map *winner = g_dexc[i].map;
            pthread_mutex_unlock(&g_dexc_lock);
            dex_map_free(m);
            return winner;
        }
    if (g_ndexc == cap) {                 // full — drop oldest slot (FIFO).
        // Do NOT dex_map_free here: another worker may hold this map pointer
        // (returned under no lock). Leak the evicted map — bounded, see header.
        memmove(&g_dexc[0], &g_dexc[1], (cap - 1) * sizeof(g_dexc[0]));
        g_ndexc--;
    }
    g_dexc[g_ndexc].begin = begin;
    g_dexc[g_ndexc].map = m;
    g_ndexc++;
    pthread_mutex_unlock(&g_dexc_lock);
    return m;
}

// Chase one candidate ArtMethod* to its {method_idx, DexFile begin_, dexmap} via rd.
// Returns 1 on success. Split out of art_method_resolve so nterp_pick can corroborate
// the candidate (dex_lookup_range needs begin_ + map) before committing to the name.
int art_method_chase(art_reader rd, void *rc, const struct art_offsets *o,
                     uint64_t artmethod, uint32_t *midx_out, uint64_t *begin_out,
                     struct dex_method_map **map_out)
{
    // Implausible / misaligned pointer — not an ArtMethod.
    if (artmethod < 0x1000 || (artmethod & 7))
        return 0;
    if (!o)
        return 0;

    uint32_t decl;
    if (!rd_u32(rd, rc, artmethod + o->artm_declclass, &decl) || decl == 0)
        return 0;
    uint64_t cls = decl;                         // zero-extend compressed ref

    uint32_t midx;
    if (!rd_u32(rd, rc, artmethod + o->artm_dexidx, &midx))
        return 0;

    uint32_t dcref;
    if (!rd_u32(rd, rc, cls + o->class_dexcache, &dcref) || dcref == 0)
        return 0;
    uint64_t dexcache = dcref;                    // zero-extend compressed ref

    uint64_t dexfile;
    if (!rd_u64(rd, rc, dexcache + o->dexcache_dexfile, &dexfile) || dexfile == 0)
        return 0;
    dexfile = ART_PTR_UNTAG(dexfile);   // DexCache.dex_file_ is a full native ptr;
                                        // Android top-byte tags it (TBI) on some targets.

    uint64_t begin, dsize;
    if (!rd_u64(rd, rc, dexfile + o->dexfile_begin, &begin) || begin == 0)
        return 0;
    begin = ART_PTR_UNTAG(begin);       // DexFile.begin_ likewise; used for image reads.
    if (!rd_u64(rd, rc, dexfile + o->dexfile_datasize, &dsize))
        return 0;
    if (dsize < 0x70 || dsize > (64u << 20))      // sane DEX image bounds
        return 0;

    struct dex_method_map *m = dexmap_get(rd, rc, begin, dsize);
    if (!m)
        return 0;

    if (midx_out)  *midx_out  = midx;
    if (begin_out) *begin_out = begin;
    if (map_out)   *map_out   = m;
    return 1;
}

int art_method_resolve(art_reader rd, void *rc, const struct art_offsets *o,
                       uint64_t artmethod, char *out, size_t outsz)
{
    uint32_t midx;
    struct dex_method_map *map;
    if (!art_method_chase(rd, rc, o, artmethod, &midx, NULL, &map))
        return 0;
    return dex_name_by_index(map, midx, out, outsz);
}

// ---- production reader: /proc/<pid>/mem ----------------------------------------
static size_t pm_reader(void *ctx, uint64_t va, void *dst, size_t len)
{
    return proc_mem_read((int)(intptr_t)ctx, va, dst, len);
}

int nterp_pick(art_reader rd, void *rc, const struct art_offsets *o,
               const uint8_t *stack, uint64_t stack_base,
               size_t stack_len, uint64_t nterp_sp, char *out, size_t outsz)
{
    if (!stack || !out || outsz == 0)
        return 0;

    int  have_fallback = 0;
    char fallback[256];

    // Scan candidate ArtMethod* slots upward from nterp_helper's SP; the managed
    // frame base (ArtMethod* at offset 0) sits just above it. Accept the FIRST
    // corroborated candidate (ascending => closest to nterp_sp); a stale spilled
    // ArtMethod* has no matching dex_pc beside it and is skipped.
    for (uint64_t off = 0; off <= NTERP_SCAN_WIN; off += 8) {
        uint64_t addr = nterp_sp + off;
        if (addr < stack_base)
            continue;
        size_t so = (size_t)(addr - stack_base);
        if (so + 8 > stack_len)
            break;
        uint64_t cand;
        memcpy(&cand, stack + so, 8);

        uint32_t midx;
        uint64_t begin;
        struct dex_method_map *map;
        if (!art_method_chase(rd, rc, o, cand, &midx, &begin, &map))
            continue;

        // Corroborate: search just above this slot for a stack value that is a live
        // dex_pc pointing into THIS method's own bytecode (same method_idx).
        int corrob = 0;
        uint32_t dexpc = 0;
        for (uint64_t c = 0; c <= NTERP_CORROB_SPAN; c += 8) {
            uint64_t va = addr + c;
            if (va < stack_base)
                continue;
            size_t cso = (size_t)(va - stack_base);
            if (cso + 8 > stack_len)
                break;
            uint64_t v;
            memcpy(&v, stack + cso, 8);
            if (v < begin)
                continue;
            uint64_t rel = v - begin;
            if (rel > 0xffffffffULL)
                continue;
            uint32_t rmidx, rinsns;
            if (dex_lookup_range(map, (uint32_t)rel, &rmidx, &rinsns) && rmidx == midx) {
                corrob = 1;
                dexpc = ((uint32_t)rel - rinsns) / 2;
                break;
            }
        }

        if (corrob) {
            char nm[256];
            if (!dex_name_by_index(map, midx, nm, sizeof(nm)))
                continue;  /* intentional: unnameable corroborated method cannot serve as fallback; a later slot may still name one */
            snprintf(out, outsz, "%s+0x%x", nm, dexpc);
            return 1;
        }
        if (!have_fallback && dex_name_by_index(map, midx, fallback, sizeof(fallback)))
            have_fallback = 1;
    }

    if (have_fallback) {
        snprintf(out, outsz, "%s?", fallback);   /* uncorroborated: mark unverified */
        return 1;
    }
    return 0;
}

int nterp_name(int pid, const struct ares_stack_snapshot *snap, uint64_t nterp_sp,
               char *out, size_t outsz)
{
    if (!snap || !out || outsz == 0)
        return 0;
    const struct art_offsets *o = art_buildid_offsets(pid);
    if (!o)
        return 0;

    int fd = proc_mem_open(pid);
    if (fd < 0)
        return 0;
    int ret = nterp_pick(pm_reader, (void *)(intptr_t)fd, o,
                         snap->snap, snap->sp, (size_t)snap->snap_len,
                         nterp_sp, out, outsz);
    close(fd);
    return ret;
}

// Scan the whole interpreted call chain above the nterp terminal at nterp_sp.
// Same corroboration loop as nterp_pick but continues past the first hit: emits
// every dex_pc-corroborated frame innermost-first, deduping consecutive identical
// ArtMethod* pointers. Uncorroborated candidates are dropped (precision over recall).
int nterp_chain_pick(art_reader rd, void *rc, const struct art_offsets *o,
                     const uint8_t *stack, uint64_t stack_base,
                     size_t stack_len, uint64_t nterp_sp, char out[][256], int max_frames)
{
    if (!stack || !out || max_frames <= 0)
        return 0;
    int nc = 0;
    uint64_t last_art = 0;
    for (uint64_t off = 0; off <= NTERP_SCAN_WIN && nc < max_frames; off += 8) {
        uint64_t addr = nterp_sp + off;
        if (addr < stack_base)
            continue;
        size_t so = (size_t)(addr - stack_base);
        if (so + 8 > stack_len)
            break;
        uint64_t cand;
        memcpy(&cand, stack + so, 8);
        if (cand == last_art)
            continue;

        uint32_t midx; uint64_t begin; struct dex_method_map *map;
        if (!art_method_chase(rd, rc, o, cand, &midx, &begin, &map))
            continue;

        /* Corroborate: a stack value above this slot that is a live dex_pc into
         * THIS method's own bytecode (same method_idx). */
        int corrob = 0;
        uint32_t dexpc = 0;
        for (uint64_t c = 0; c <= NTERP_CORROB_SPAN; c += 8) {
            uint64_t va = addr + c;
            if (va < stack_base)
                continue;
            size_t cso = (size_t)(va - stack_base);
            if (cso + 8 > stack_len)
                break;
            uint64_t v;
            memcpy(&v, stack + cso, 8);
            if (v < begin)
                continue;
            uint64_t rel = v - begin;
            if (rel > 0xffffffffULL)
                continue;
            uint32_t rmidx, rinsns;
            if (dex_lookup_range(map, (uint32_t)rel, &rmidx, &rinsns) && rmidx == midx) {
                corrob = 1;
                dexpc = ((uint32_t)rel - rinsns) / 2;
                break;
            }
        }
        if (!corrob)
            continue;                 /* precision over recall */

        char nm[240];   /* 240 + "+0x" + 8 hex digits = 251 < 256: no truncation */
        if (!dex_name_by_index(map, midx, nm, sizeof(nm)))
            continue;
        snprintf(out[nc], 256, "%s+0x%x", nm, dexpc);
        last_art = cand;
        nc++;
    }
    return nc;
}

int nterp_chain(int pid, const struct ares_stack_snapshot *snap, uint64_t nterp_sp,
                char out[][256], int max_frames)
{
    if (!snap || !out || max_frames <= 0)
        return 0;
    const struct art_offsets *o = art_buildid_offsets(pid);
    if (!o)
        return 0;
    int fd = proc_mem_open(pid);
    if (fd < 0)
        return 0;
    int nc = nterp_chain_pick(pm_reader, (void *)(intptr_t)fd, o,
                              snap->snap, snap->sp, (size_t)snap->snap_len,
                              nterp_sp, out, max_frames);
    close(fd);
    return nc;
}
