// SPDX-License-Identifier: GPL-2.0
// Host unit test for the pure aux/pid selection helpers in common/sym_pid.h.
#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include "common/sym_pid.h"

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

int main(void)
{
    // aux pack/unpack: ppid in the low 31 bits, exec flag in bit 31.
    __u32 a = sym_aux_make(4321, 1);
    CHECK(a == (4321u | SYM_AUX_EXEC), "aux_make sets exec flag");
    CHECK(sym_aux_ppid(a) == 4321, "aux_ppid recovers parent tgid");
    CHECK(sym_aux_is_exec(a) == 1, "aux_is_exec reads flag");
    CHECK(sym_aux_is_exec(sym_aux_make(4321, 0)) == 0, "aux_make without flag");
    CHECK(sym_aux_make(0, 1) == 0, "ppid 0 encodes unknown (flag dropped)");
    CHECK(sym_aux_make(-5, 1) == 0, "negative ppid encodes unknown");

    // Pick the parent only when it is usable and the child's own maps cannot
    // describe the recorded frames.
    CHECK(sym_pick_pid(100, sym_aux_make(50, 0), 1) == 50,
          "child maps gone -> parent");
    CHECK(sym_pick_pid(100, sym_aux_make(50, 0), 0) == 100,
          "live child, non-exec -> own pid");
    CHECK(sym_pick_pid(100, sym_aux_make(50, 1), 0) == 50,
          "exec event -> parent even while child lives");
    CHECK(sym_pick_pid(100, 0, 1) == 100,
          "unknown aux -> own pid");
    CHECK(sym_pick_pid(100, sym_aux_make(100, 1), 1) == 100,
          "ppid == pid -> own pid");
    CHECK(sym_pick_pid(100, sym_aux_make(1, 1), 1) == 100,
          "reparented to init -> own pid");
    CHECK(sym_pick_pid(100, sym_aux_make(0, 1), 1) == 100,
          "ppid 0 -> own pid");

    // The parent lookup matters only for exec events and for a process's
    // single-threaded pre-exec phase, where tid == tgid.
    CHECK(sym_aux_wanted(0, 100, 100) == 1,
          "leader thread -> parent read wanted");
    CHECK(sym_aux_wanted(0, 100, 101) == 0,
          "non-leader thread -> parent read skipped");
    CHECK(sym_aux_wanted(1, 100, 101) == 1,
          "exec from any thread -> parent read wanted");

    // Per-pid decision cache: direct mapped, alive and gone TTLs differ.
    struct sym_pidc cache = {0};
    int gone = -1;
    CHECK(sym_pidc_get(&cache, 100, 1100, &gone) == 0,
          "empty cache -> miss");

    sym_pidc_put(&cache, 100, 0, 1000);
    CHECK(sym_pidc_get(&cache, 100, 1100, &gone) == 1 && gone == 0,
          "alive entry hits before TTL");
    CHECK(sym_pidc_get(&cache, 100, 1251, &gone) == 0,
          "alive entry expires after 250 ms");

    sym_pidc_put(&cache, 100, 1, 1000);
    CHECK(sym_pidc_get(&cache, 100, 5999, &gone) == 1 && gone == 1,
          "gone entry hits before TTL");
    CHECK(sym_pidc_get(&cache, 100, 6001, &gone) == 0,
          "gone entry expires after 5000 ms");

    // Pids separated by the slot count share a direct-mapped slot.
    struct sym_pidc collisions = {0};
    sym_pidc_put(&collisions, 100, 0, 1000);
    sym_pidc_put(&collisions, 100 + SYM_PIDC_SLOTS, 0, 1000);
    CHECK(sym_pidc_get(&collisions, 100, 1100, &gone) == 0,
          "colliding pid replaces the old entry");
    CHECK(sym_pidc_get(&collisions, 100 + SYM_PIDC_SLOTS, 1100, &gone) == 1 &&
          gone == 0,
          "new colliding pid hits");

    // A zeroed cache must look empty even for pid 0.
    struct sym_pidc zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    CHECK(sym_pidc_get(&zeroed, 0, 1000, &gone) == 0,
          "pid 0 never hits a zeroed cache");
    CHECK(sym_pidc_get(&zeroed, 100, 1000, &gone) == 0,
          "zeroed cache has no entries");

    // Parent tgid memory: a leader or exec event records the parent tgid, so a
    // later event of the same pid without aux still resolves against it.
    static struct sym_ppidc pc;
    __u32 got;

    CHECK(sym_ppidc_resolve(&pc, 100, 0) == 0,
          "empty parent table -> unknown stays unknown");
    CHECK(sym_ppidc_resolve(&pc, 100, sym_aux_make(50, 0)) == sym_aux_make(50, 0),
          "leader event passes through and is remembered");
    got = sym_ppidc_resolve(&pc, 100, 0);
    CHECK(got == sym_aux_make(50, 0),
          "later aux-less event of the same pid gets the parent");
    CHECK(sym_pick_pid(100, got, 1) == 50,
          "remembered parent is used when the child's maps are gone");
    CHECK(sym_pick_pid(100, got, 0) == 100,
          "alive child stays on its own pid");
    CHECK(sym_aux_is_exec(got) == 0,
          "remembered parent does not invent the exec flag");
    CHECK(sym_ppidc_resolve(&pc, 100, sym_aux_make(50, 1)) == sym_aux_make(50, 1),
          "exec event keeps its flag");
    CHECK(sym_ppidc_resolve(&pc, 101, 0) == 0,
          "other pid is unaffected");

    // Direct-mapped slots: pids separated by the slot count collide.
    CHECK(sym_ppidc_resolve(&pc, 100 + SYM_PPIDC_SLOTS, sym_aux_make(70, 0)) ==
          sym_aux_make(70, 0),
          "colliding pid records its parent");
    CHECK(sym_ppidc_resolve(&pc, 100, 0) == 0,
          "collision replaces the old parent entry");

    // A new leader event of a reused pid replaces the remembered parent.
    CHECK(sym_ppidc_resolve(&pc, 100, sym_aux_make(60, 0)) == sym_aux_make(60, 0),
          "reused pid records its new parent");
    CHECK(sym_ppidc_resolve(&pc, 100, 0) == sym_aux_make(60, 0),
          "reused pid resolves to the new parent");

    // Pid 0 and negative pids are not table keys.
    CHECK(sym_ppidc_resolve(&pc, 0, 0) == 0,
          "pid 0 resolves to unknown");
    CHECK(sym_ppidc_resolve(&pc, -1, sym_aux_make(5, 0)) == sym_aux_make(5, 0),
          "negative pid passes the aux through");
    CHECK(sym_ppidc_resolve(&pc, 0, 0) == 0,
          "pid 0 stored nothing");
    CHECK(sym_ppidc_resolve(&pc, -1, 0) == 0,
          "negative pid stored nothing");

    if (fails) { printf("FAILED: %d check(s)\n", fails); return 1; }
    printf("test_sym_pid: all checks passed\n");
    return 0;
}
