// SPDX-License-Identifier: GPL-2.0
// Host unit test for the versioned per-(engine, pid) maps model in
// common/sym_procmaps.c: map/unmap events applied in sequence order.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "common/symbolize_internal.h"
#include "common/maps.h"

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

// pm_alloc_e calls this on eviction; symbolize.c owns the real hook.
void pm_evict_pid(int pid)
{
    (void)pid;
}

static const char *path_at(int engine, int pid, uint64_t addr, uint64_t seq)
{
    struct procmaps *pm = pm_find_e(engine, pid);
    struct anubee_map_line *hit = pm ? find_mapping_at(pm, addr, seq) : NULL;

    return hit ? hit->path : NULL;
}

static int is_path(const char *got, const char *want)
{
    return got && strcmp(got, want) == 0;
}

static int maps_has_range(int pid, uint64_t s, uint64_t e)
{
    char path[64];
    FILE *f;
    char line[512];
    struct anubee_map_line m;
    int found = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!anubee_parse_maps_line(line, &m))
            continue;
        if (m.start < e && m.end > s) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int first_line_with_exec(int pid, struct anubee_map_line *out)
{
    char path[64];
    FILE *f;
    char line[512];

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!anubee_parse_maps_line(line, out))
            continue;
        if (out->exec) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int first_line(int pid, struct anubee_map_line *out)
{
    char path[64];
    FILE *f;
    char line[512];
    int got = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!anubee_parse_maps_line(line, out))
            continue;
        got = 1;
        break;
    }
    fclose(f);
    return got;
}

static void test_map_then_lookup(void)
{
    int pid = 0x7f000000;
    struct procmaps *pm;
    struct anubee_map_line *hit;

    pm_apply_map(1, pid, 10, 0x1000, 0x2000, 0, 1, 1, "/a.so");
    CHECK(is_path(path_at(1, pid, 0x1800, 11), "/a.so"),
          "map: visible at a later seq");
    CHECK(path_at(1, pid, 0x1800, 9) == NULL,
          "map: not visible before add_seq");
    CHECK(is_path(path_at(1, pid, 0x1800, SYM_SEQ_LIVE), "/a.so"),
          "map: visible at the live seq");
    pm = pm_find_e(1, pid);
    hit = pm ? find_mapping_at(pm, 0x1800, 11) : NULL;
    CHECK(hit && hit->inode == 1 && hit->dev == 1 && hit->exec == 1 &&
          hit->id != 0, "map: inode/dev/exec/id recorded");
}

static void test_teardown_burst(void)
{
    int pid = 0x7f010000;
    char path[32];
    uint64_t base, addr;
    int i;

    pm_apply_map(1, pid, 10, 0x1000, 0x2000, 0, 1, 1, "/a.so");
    pm_apply_unmap(1, pid, 20, 0x1000, 0x2000);
    CHECK(path_at(1, pid, 0x1800, 15) != NULL,
          "teardown: live before unmap");
    CHECK(path_at(1, pid, 0x1800, 25) == NULL,
          "teardown: gone after unmap");
    CHECK(path_at(1, pid, 0x1800, SYM_SEQ_LIVE) == NULL,
          "teardown: gone at the live seq");

    for (i = 0; i < 40; i++) {
        base = 0x100000 + (uint64_t)i * 0x1000;
        snprintf(path, sizeof(path), "/l%d.so", i);
        pm_apply_map(1, pid, (uint64_t)(100 + i), base, base + 0x1000,
                     0, (uint64_t)(i + 1), 1, path);
    }
    for (i = 0; i < 40; i++) {
        base = 0x100000 + (uint64_t)i * 0x1000;
        pm_apply_unmap(1, pid, (uint64_t)(200 + i), base, base + 0x1000);
    }
    for (i = 0; i < 40; i++) {
        base = 0x100000 + (uint64_t)i * 0x1000;
        addr = base + 0x800;
        snprintf(path, sizeof(path), "/l%d.so", i);
        CHECK(is_path(path_at(1, pid, addr, 150), path),
              "teardown: every lib still visible before the burst");
    }
}

static void test_mprotect_split(void)
{
    int pid = 0x7f020000;
    struct procmaps *pm;
    struct anubee_map_line *hit;

    pm_apply_map(1, pid, 10, 0x1000, 0x3000, 0, 1, 1, "/m.so");
    pm_apply_unmap(1, pid, 20, 0x1000, 0x3000);
    pm_apply_map(1, pid, 21, 0x2000, 0x3000, 1, 1, 1, "/m.so");
    pm = pm_find_e(1, pid);
    hit = pm ? find_mapping_at(pm, 0x2800, 22) : NULL;
    CHECK(hit && is_path(hit->path, "/m.so"),
          "mprotect: remapped half visible later");
    CHECK(path_at(1, pid, 0x1800, 22) == NULL,
          "mprotect: dropped half invisible later");
    CHECK(path_at(1, pid, 0x1800, 15) != NULL,
          "mprotect: dropped half visible earlier");
    if (sysconf(_SC_PAGESIZE) == 4096)
        CHECK(hit && hit->off == 0x1000, "mprotect: page offset applied");
    else
        printf("note: page size is not 4096, skipping offset checks\n");
}

static void test_partial_unmap_keeps_rest(void)
{
    int pid = 0x7f030000;
    struct procmaps *pm;
    struct anubee_map_line *hit;

    pm_apply_map(1, pid, 10, 0x1000, 0x4000, 0, 1, 1, "/p.so");
    pm_apply_unmap(1, pid, 20, 0x2000, 0x3000);
    pm = pm_find_e(1, pid);
    CHECK(path_at(1, pid, 0x1800, 21) != NULL,
          "partial: left remainder visible");
    hit = pm ? find_mapping_at(pm, 0x3800, 21) : NULL;
    CHECK(hit != NULL, "partial: right remainder visible");
    CHECK(hit && hit->off == 0x2000, "partial: right remainder offset");
    CHECK(hit && hit->add_seq == 20, "partial: remainder added at unmap seq");
    CHECK(path_at(1, pid, 0x2800, 21) == NULL,
          "partial: unmapped middle gone");
    CHECK(path_at(1, pid, 0x2800, 15) != NULL,
          "partial: middle visible before unmap");
}

static void test_map_over_live_line(void)
{
    int pid = 0x7f040000;
    struct procmaps *pm;
    size_t i, cnt = 0;

    pm_apply_map(1, pid, 10, 0x1000, 0x2000, 0, 1, 1, "/old.so");
    pm_apply_map(1, pid, 20, 0x1000, 0x2000, 0, 1, 1, "/new.so");
    CHECK(is_path(path_at(1, pid, 0x1800, 15), "/old.so"),
          "overmap: old version visible before");
    CHECK(is_path(path_at(1, pid, 0x1800, 25), "/new.so"),
          "overmap: new version visible after");
    pm = pm_find_e(1, pid);
    if (pm)
        for (i = 0; i < pm->n; i++)
            if (pm->m[i].start == 0x1000 && pm->m[i].end == 0x2000)
                cnt++;
    CHECK(cnt == 1, "overmap: exactly one live line in that range");
}

static void test_seed_from_parent_at_seq(void)
{
    int ppid = 0x7f050000;
    int child = 0x7f050001;

    pm_apply_map(1, ppid, 5, 0x1000, 0x2000, 0, 1, 1, "/a.so");
    pm_apply_map(1, ppid, 30, 0x5000, 0x6000, 0, 1, 1, "/b.so");
    pm_seed_from_parent(1, child, ppid, 20);
    CHECK(is_path(path_at(1, child, 0x1800, SYM_SEQ_LIVE), "/a.so"),
          "parent seed: line valid at seq copied");
    CHECK(path_at(1, child, 0x5800, SYM_SEQ_LIVE) == NULL,
          "parent seed: later line not copied");
    pm_apply_map(1, ppid, 40, 0x9000, 0xa000, 0, 1, 1, "/c.so");
    CHECK(path_at(1, child, 0x9800, SYM_SEQ_LIVE) == NULL,
          "parent seed: child is a copy, not a view");
    pm_seed_from_parent(1, child, ppid, 50);
    CHECK(path_at(1, child, 0x5800, SYM_SEQ_LIVE) == NULL,
          "parent seed: second call leaves the seeded child alone");
}

static void test_engines_isolated(void)
{
    int pid = 0x7f060000;

    pm_apply_map(1, pid, 10, 0x1000, 0x2000, 0, 1, 1, "/e.so");
    CHECK(path_at(2, pid, 0x1800, SYM_SEQ_LIVE) == NULL,
          "engines: same pid is isolated per engine");
}

static void test_compact(void)
{
    int pid = 0x7f070000;

    pm_apply_map(1, pid, 10, 0x1000, 0x2000, 0, 1, 1, "/k.so");
    pm_apply_unmap(1, pid, 20, 0x1000, 0x2000);
    pm_compact(1, 19);
    CHECK(path_at(1, pid, 0x1800, 15) != NULL,
          "compact: retired line kept while still needed");
    pm_compact(1, 25);
    CHECK(path_at(1, pid, 0x1800, 15) == NULL,
          "compact: retired line dropped once no event needs it");
}

static void test_dirty_merge_never_retires(void)
{
    int self = (int)getpid();
    struct procmaps *pm;
    struct anubee_map_line first;
    int have_first;

    memset(&first, 0, sizeof(first));
    CHECK(!maps_has_range(self, 0x30000, 0x31000),
          "dirty merge: fake range is absent");
    CHECK(!maps_has_range(self, 0x50000, 0x51000),
          "dirty merge: probe range is absent");
    pm_apply_map(1, self, 10, 0x30000, 0x31000, 0, 7, 7, "/fake.so");
    pm = pm_find_e(1, self);
    CHECK(pm != NULL, "dirty merge: model exists");
    pm_mark_dirty_all(1);
    CHECK(pm && pm->dirty == 1, "dirty merge: model marked dirty");
    if (pm) {
        CHECK(find_mapping_refresh_at(pm, 0x50000, SYM_SEQ_LIVE) == NULL,
              "dirty merge: absent range still misses");
        CHECK(pm->dirty == 0, "dirty merge: reread clears dirty");
        CHECK(is_path(path_at(1, self, 0x30100, SYM_SEQ_LIVE), "/fake.so"),
              "dirty merge: event line never retired");
        have_first = first_line(self, &first);
        CHECK(have_first, "dirty merge: read /proc maps");
        CHECK(have_first && path_at(1, self, first.start, SYM_SEQ_LIVE) != NULL,
              "dirty merge: real line merged or kept");
    }
}

static void test_merge_adds_missing(void)
{
    int self = (int)getpid();
    struct procmaps *pm;
    struct anubee_map_line x;
    struct anubee_map_line *hit;
    int have_x;

    memset(&x, 0, sizeof(x));
    pm = pm_get_e(3, self);
    CHECK(pm != NULL, "merge adds: model seeded");
    have_x = first_line_with_exec(self, &x);
    CHECK(have_x, "merge adds: found exec line");
    if (!pm || !have_x) {
        printf("note: skipping merge-adds checks (no model or line)\n");
        return;
    }
    pm_apply_unmap(3, self, 50, x.start, x.end);
    CHECK(find_mapping_at(pm, x.start, 40) != NULL,
          "merge adds: retired version visible at an earlier seq");
    CHECK(find_mapping_at(pm, x.start, SYM_SEQ_LIVE) == NULL,
          "merge adds: line missing before reread");
    pm->stale = 1;
    hit = find_mapping_refresh_at(pm, x.start, SYM_SEQ_LIVE);
    CHECK(hit != NULL, "merge adds: reread restores the line");
    CHECK(hit && hit->add_seq == 50,
          "merge adds: restored line starts at the pending seq");
    hit = find_mapping_at(pm, x.start, 40);
    CHECK(hit && hit->del_seq == 50,
          "merge adds: retired version still available");
}

static void test_evict_exited_first(void)
{
    int base = 0x7f400000;
    int i, created = 0;

    for (i = 0; i < 1024; i++)
        if (pm_get_e(1, base + i))
            created++;
    CHECK(created == 1024, "evict: filled the pool with 1024 models");
    pm_note_exit(1, base + 500);
    CHECK(pm_get_e(1, base + 5000) != NULL, "evict: one more model made");
    CHECK(pm_find_e(1, base + 500) == NULL,
          "evict: exited model evicted first");
    CHECK(pm_find_e(1, base + 5000) != NULL,
          "evict: new model is present");
    CHECK(pm_find_e(1, base + 501) != NULL,
          "evict: neighbour model kept");
}

static void test_legacy_engine0(void)
{
    struct procmaps *pm = pm_get((int)getpid());
    size_t i;
    int ok = 1;

    CHECK(pm != NULL, "legacy: pm_get returns a model");
    CHECK(pm && pm->engine == 0, "legacy: engine is 0");
    CHECK(pm && pm->n > 0, "legacy: model has mappings");
    if (pm) {
        for (i = 0; i < pm->n; i++)
            if (pm->m[i].id == 0 || pm->m[i].add_seq != 0 ||
                pm->m[i].del_seq != SYM_SEQ_LIVE)
                ok = 0;
        CHECK(ok, "legacy: lines carry ids and are live from seq 0");
    }
}

int main(void)
{
    test_map_then_lookup();
    test_teardown_burst();
    test_mprotect_split();
    test_partial_unmap_keeps_rest();
    test_map_over_live_line();
    test_seed_from_parent_at_seq();
    test_engines_isolated();
    test_compact();
    test_dirty_merge_never_retires();
    test_merge_adds_missing();
    test_evict_exited_first();
    test_legacy_engine0();

    if (fails) { printf("FAILED: %d check(s)\n", fails); return 1; }
    printf("test_pm_events: all checks passed\n");
    return 0;
}
