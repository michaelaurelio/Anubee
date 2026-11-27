// SPDX-License-Identifier: GPL-2.0
// Host unit test for the /proc/<pid>/maps snapshot retention in
// common/sym_procmaps.c: a vanished process keeps its last known mappings.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common/symbolize_internal.h"

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

// pm_get calls this when it evicts the LRU slot; symbolize.c owns the real
// hook, which only resets the other per-pid caches.
void pm_evict_pid(int pid)
{
    (void)pid;
}

// Above the kernel's pid_max, so /proc/<pid>/maps can never exist.
static int nonexistent_pid(void)
{
    return 0x7ffffff0;
}

int main(void)
{
    // A live process's maps read fills the snapshot.
    struct procmaps *pm = pm_get((int)getpid());
    CHECK(pm != NULL, "pm_get returns a slot for the live process");
    if (!pm) {
        printf("FAILED: %d check(s)\n", fails);
        return 1;
    }
    CHECK(pm->n > 0, "live process has mappings");
    CHECK(pm->gone == 0, "live process is not gone");

    // Fixture: never-used pid (the maps file does not exist).
    struct procmaps fresh;
    memset(&fresh, 0, sizeof(fresh));
    fresh.pid = nonexistent_pid();
    read_proc_maps(&fresh);
    CHECK(fresh.gone == 1, "ENOENT marks the pid gone");
    CHECK(fresh.n == 0, "ENOENT leaves an empty snapshot empty");

    // Fixture: dead pid that held a snapshot (the next read fails with ENOENT).
    size_t n0 = pm->n;
    uint64_t start0 = pm->m[0].start;
    int live_pid = (int)getpid();
    pm->pid = nonexistent_pid();
    read_proc_maps(pm);
    CHECK(pm->gone == 1, "dead pid marks its snapshot gone");
    CHECK(pm->n == n0, "dead pid keeps the mapping count");
    CHECK(pm->n > 0 && pm->m[0].start == start0,
          "dead pid keeps the mappings");

    // Fixture: library flush on a live pid. A reset marks the snapshot stale;
    // the next lookup rereads the live maps and clears the mark.
    pm->pid = live_pid;
    read_proc_maps(pm);
    CHECK(pm->n > 0 && pm->gone == 0, "live reread restores the snapshot");
    pm_reset_pid(live_pid);
    CHECK(pm->stale == 1, "pm_reset_pid marks the snapshot stale");
    CHECK(pm->n > 0, "pm_reset_pid keeps the snapshot");
    struct anubee_map_line *hit = find_mapping_refresh(pm, pm->m[0].start);
    CHECK(hit != NULL, "stale live snapshot is reread on lookup");
    CHECK(pm->stale == 0, "live reread clears the stale mark");
    CHECK(pm->gone == 0, "live reread is not gone");

    // Fixture: library flush racing process death. The reread fails with
    // ENOENT, so the retained snapshot still answers the lookup.
    size_t n1 = pm->n;
    uint64_t start1 = pm->m[0].start;
    pm->pid = nonexistent_pid();
    pm_reset_pid(nonexistent_pid());
    CHECK(pm->stale == 1, "dead pid reset marks the snapshot stale");
    hit = find_mapping_refresh(pm, start1);
    CHECK(hit != NULL, "stale dead snapshot still answers the lookup");
    CHECK(pm->n == n1 && pm->m[0].start == start1,
          "dead reread keeps the mappings");
    CHECK(pm->gone == 1, "dead reread marks the pid gone");
    CHECK(pm->stale == 0, "dead reread clears the stale mark");

    if (fails) { printf("FAILED: %d check(s)\n", fails); return 1; }
    printf("test_pm_retain: all checks passed\n");
    return 0;
}
