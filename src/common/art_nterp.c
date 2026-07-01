// SPDX-License-Identifier: GPL-2.0
// art_nterp.c — see art_nterp.h. Names interpreted (nterp) Java frames by chasing
// ART runtime structs out-of-process. All reads, no writes (firewall-clean).
//
// Offset table (ART apex 370549100, Android 15, arm64) — verified against AOSP
// android15-release; see the spike findings doc. References are 32-bit compressed:
// decompress = zero-extend (no heap base; poisoning is off on release builds).
#include "common/art_nterp.h"
#include "common/dex.h"
#include "common/proc_mem.h"

#include <linux/types.h>          /* __u32/__u64 for stack_snapshot.h */
#include "common/stack_snapshot.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>

// ---- version-coupled offsets ---------------------------------------------------
#define ARTM_DECLCLASS_OFF    0x00  // ArtMethod.declaring_class_ (compressed ref)
#define ARTM_DEXIDX_OFF       0x08  // ArtMethod.dex_method_index_ (u32)
#define CLASS_DEXCACHE_OFF    0x10  // mirror::Class.dex_cache_ (compressed ref)
#define DEXCACHE_DEXFILE_OFF  0x10  // mirror::DexCache.dex_file_ (native DexFile*)
#define DEXFILE_BEGIN_OFF     0x08  // DexFile.begin_ (const u8*)
#define DEXFILE_DATASIZE_OFF  0x20  // DexFile.data_.size_ (size_t) — NOT +0x10:
                                    // size_ was renamed unused_size_=0 on A15.

// How far above nterp_helper's SP to scan for the managed frame's ArtMethod*.
// nterp's native helper frames vary in size, so the managed frame base can sit a
// few KB up; a generous window costs only deduped per-stack work.
#define NTERP_SCAN_WIN  4096

// Known ART apex versions whose offsets match the table above.
static const long KNOWN_ART_APEX[] = { 370549100 };

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
static int art_method_chase(art_reader rd, void *rc, uint64_t artmethod,
                            uint32_t *midx_out, uint64_t *begin_out,
                            struct dex_method_map **map_out)
{
    // Implausible / misaligned pointer — not an ArtMethod.
    if (artmethod < 0x1000 || (artmethod & 7))
        return 0;

    uint32_t decl;
    if (!rd_u32(rd, rc, artmethod + ARTM_DECLCLASS_OFF, &decl) || decl == 0)
        return 0;
    uint64_t cls = decl;                         // zero-extend compressed ref

    uint32_t midx;
    if (!rd_u32(rd, rc, artmethod + ARTM_DEXIDX_OFF, &midx))
        return 0;

    uint32_t dcref;
    if (!rd_u32(rd, rc, cls + CLASS_DEXCACHE_OFF, &dcref) || dcref == 0)
        return 0;
    uint64_t dexcache = dcref;                    // zero-extend compressed ref

    uint64_t dexfile;
    if (!rd_u64(rd, rc, dexcache + DEXCACHE_DEXFILE_OFF, &dexfile) || dexfile == 0)
        return 0;

    uint64_t begin, dsize;
    if (!rd_u64(rd, rc, dexfile + DEXFILE_BEGIN_OFF, &begin) || begin == 0)
        return 0;
    if (!rd_u64(rd, rc, dexfile + DEXFILE_DATASIZE_OFF, &dsize))
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

int art_method_resolve(art_reader rd, void *rc, uint64_t artmethod,
                       char *out, size_t outsz)
{
    uint32_t midx;
    struct dex_method_map *map;
    if (!art_method_chase(rd, rc, artmethod, &midx, NULL, &map))
        return 0;
    return dex_name_by_index(map, midx, out, outsz);
}

// ---- ART version gate ----------------------------------------------------------
static int art_version_ok(void)
{
    static int cached = -1;          // -1 unknown, 0 no, 1 yes
    if (cached >= 0)
        return cached;
    cached = 0;
    DIR *d = opendir("/apex");
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        const char *p = strstr(e->d_name, "com.android.art@");
        if (p != e->d_name)
            continue;
        long v = strtol(e->d_name + strlen("com.android.art@"), NULL, 10);
        for (size_t i = 0; i < sizeof(KNOWN_ART_APEX) / sizeof(KNOWN_ART_APEX[0]); i++)
            if (v == KNOWN_ART_APEX[i]) { cached = 1; break; }
        if (cached)
            break;
    }
    closedir(d);
    return cached;
}

// ---- production reader: /proc/<pid>/mem ----------------------------------------
static size_t pm_reader(void *ctx, uint64_t va, void *dst, size_t len)
{
    return proc_mem_read((int)(intptr_t)ctx, va, dst, len);
}

int nterp_name(int pid, const struct ares_stack_snapshot *snap, uint64_t nterp_sp,
               char *out, size_t outsz)
{
    if (!snap || !out || outsz == 0)
        return 0;
    if (!art_version_ok())
        return 0;

    int fd = proc_mem_open(pid);
    if (fd < 0)
        return 0;
    void *rc = (void *)(intptr_t)fd;

    int ret = 0;
    // The ArtMethod* is at the managed nterp frame's base, just above nterp_helper's
    // SP. Its exact offset isn't known (the terminal step failed, so its CFA is
    // unset), so scan a bounded window upward and validate each candidate by whether
    // the full ArtMethod->DexFile chase yields a real method name. Candidates are
    // read from the frozen snapshot stack bytes (point-in-time correct).
    for (uint64_t off = 0; off <= NTERP_SCAN_WIN; off += 8) {
        uint64_t addr = nterp_sp + off;
        if (addr < snap->sp)
            continue;
        size_t so = (size_t)(addr - snap->sp);
        if (so + 8 > snap->snap_len)
            break;
        uint64_t cand;
        memcpy(&cand, snap->snap + so, 8);
        if (art_method_resolve(pm_reader, rc, cand, out, outsz)) {
            ret = 1;
            break;
        }
    }
    close(fd);
    return ret;
}
