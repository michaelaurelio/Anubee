// SPDX-License-Identifier: GPL-2.0
// See target_registry.h. Moved verbatim out of src/funcs/funcs.c (funcs was
// the only caller before correlate needed the same addr->symbol resolution);
// behavior unchanged — same hash cache, same /proc/<pid>/maps miss path, same
// lower-12-bit ASLR fallback.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/maps.h"
#include "common/target_registry.h"

probe_target_t target_registry[TARGET_REGISTRY_CAP];
int target_registry_count;

// retired_targets/retired_count: entries removed by UNMAP but that may still
// have in-flight events. Carried over from funcs.c as-is — nothing populates
// this array today (pre-existing gap, not introduced by this move; out of
// scope to fix here).
static probe_target_t retired_targets[TARGET_REGISTRY_CAP];
static int retired_count;

static pthread_mutex_t g_targets_lock = PTHREAD_MUTEX_INITIALIZER; // target_registry[] + count

// addr -> probe_target_t* cache (AA4). target_registry[]+retired_targets[] cap
// at TARGET_REGISTRY_CAP each, so a fixed 16384-slot table stays <=50% loaded
// even at that ceiling (worst case, both arrays full) — no grow/rehash
// needed, unlike symbolize.c's sc_ent (which caches an unbounded (pid,addr)
// set over a trace). Guarded by g_targets_lock, same as the arrays it indexes.
#define PT_HASH_CAP (1u << 14)   /* 16384, power of 2 */
struct pt_hash_ent { __u64 addr; probe_target_t *target; int used; };
static struct pt_hash_ent pt_hash[PT_HASH_CAP];

static uint64_t pt_hash_fn(__u64 addr)
{
    uint64_t h = addr;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

// Both must be called with g_targets_lock held.
static probe_target_t *pt_hash_get(__u64 addr)
{
    size_t mask = PT_HASH_CAP - 1, i = pt_hash_fn(addr) & mask;
    for (size_t probe = 0; probe < PT_HASH_CAP; probe++) {
        struct pt_hash_ent *e = &pt_hash[i];
        if (!e->used) return NULL;
        if (e->addr == addr) return e->target;
        i = (i + 1) & mask;
    }
    return NULL;
}

static void pt_hash_put(__u64 addr, probe_target_t *target)
{
    size_t mask = PT_HASH_CAP - 1, i = pt_hash_fn(addr) & mask;
    while (pt_hash[i].used && pt_hash[i].addr != addr)
        i = (i + 1) & mask;
    pt_hash[i].used = 1;
    pt_hash[i].addr = addr;
    pt_hash[i].target = target;
}

bool target_registry_add(probe_target_t tgt)
{
    pthread_mutex_lock(&g_targets_lock);
    bool ok = target_registry_count < TARGET_REGISTRY_CAP;
    if (ok)
        target_registry[target_registry_count++] = tgt;
    pthread_mutex_unlock(&g_targets_lock);
    return ok;
}

probe_target_t *find_target_by_entry_addr(__u64 entry_addr, pid_t pid, bool *used_fallback)
{
    *used_fallback = false;
    probe_target_t *result = NULL;

    // ponytail: coarse mutex, held across the /proc miss path; per-entry locking only if contention shows.
    pthread_mutex_lock(&g_targets_lock);

    result = pt_hash_get(entry_addr);

    if (!result) {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *f = fopen(maps_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f) && !result) {
                struct ares_map_line ml;
                if (!ares_parse_maps_line(line, &ml)) continue;
                if (entry_addr < ml.start || entry_addr >= ml.end) continue;
                if (!ml.exec || ml.path[0] != '/') continue;

                unsigned long file_offset = (unsigned long)(entry_addr - ml.start)
                                          + (unsigned long)ml.off;

                for (int i = 0; i < target_registry_count; i++) {
                    if (target_registry[i].offset == file_offset &&
                        strcmp(target_registry[i].mod_path, ml.path) == 0) {
                        target_registry[i].runtime_entry_addr = entry_addr;
                        result = &target_registry[i];
                        pt_hash_put(entry_addr, &target_registry[i]);
                        break;
                    }
                }
            }
            fclose(f);
        }
    }

    // Fallback: use the lower-12-bit invariant. ASLR keeps the base page-aligned
    // (multiple of 0x1000), so (base + file_offset) & 0xFFF == file_offset & 0xFFF
    // always holds. Search both active and retired targets (retired = removed by UNMAP
    // but may still have in-flight events). Two entries with the same lower 12 bits
    // but different offset+mod_path = ambiguous, skip.
    if (!result) {
        unsigned long low12 = (unsigned long)(entry_addr & 0xFFF);
        probe_target_t *candidate = NULL;
        bool ambiguous = false;
        for (int pass = 0; pass < 2 && !ambiguous; pass++) {
            probe_target_t *arr = (pass == 0) ? target_registry : retired_targets;
            int cnt = (pass == 0) ? target_registry_count : retired_count;
            for (int i = 0; i < cnt && !ambiguous; i++) {
                if ((arr[i].offset & 0xFFF) != low12) continue;
                if (!candidate) {
                    candidate = &arr[i];
                } else if (arr[i].offset != candidate->offset ||
                           strcmp(arr[i].mod_path, candidate->mod_path) != 0) {
                    ambiguous = true;
                }
            }
        }
        if (candidate && !ambiguous) {
            candidate->runtime_entry_addr = entry_addr;
            *used_fallback = true;
            result = candidate;
            pt_hash_put(entry_addr, candidate);
        }
    }

    pthread_mutex_unlock(&g_targets_lock);
    return result;
}
