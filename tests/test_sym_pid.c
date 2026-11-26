// SPDX-License-Identifier: GPL-2.0
// Host unit test for the pure aux/pid selection helpers in common/sym_pid.h.
#include <linux/types.h>
#include <stdio.h>
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

    // The pid whose address space a recorded stack belongs to. An exec event's
    // stack predates the exec, so it belongs to the parent; every other event
    // belongs to the event's own pid.

    // Fixture: exec predating the stack.
    CHECK(sym_first_pid(100, sym_aux_make(50, 1)) == 50,
          "exec event resolves its stack against the parent");
    // Fixture: zygote-forked never-exec'd child.
    CHECK(sym_first_pid(100, sym_aux_make(50, 0)) == 100,
          "never-exec'd child keeps its own pid");
    CHECK(sym_first_pid(100, sym_aux_make(0, 0)) == 100,
          "ppid 0 -> own pid");
    CHECK(sym_first_pid(100, sym_aux_make(1, 0)) == 100,
          "reparented to init -> own pid");
    CHECK(sym_first_pid(100, sym_aux_make(100, 0)) == 100,
          "ppid == pid -> own pid");
    CHECK(sym_first_pid(100, sym_aux_make(1, 1)) == 100,
          "exec reparented to init -> own pid");
    CHECK(sym_first_pid(100, sym_aux_make(100, 1)) == 100,
          "exec with ppid == pid -> own pid");
    CHECK(sym_first_pid(100, 0) == 100,
          "unknown aux -> own pid");

    // The parent is consulted lazily, only when the child's own resolution
    // fails; an exec event already went to the parent first.
    CHECK(sym_fallback_pid(100, sym_aux_make(50, 0)) == 50,
          "non-exec with a usable parent -> fallback pid");
    CHECK(sym_fallback_pid(100, sym_aux_make(50, 1)) == 0,
          "exec resolves against the parent first -> no fallback");
    CHECK(sym_fallback_pid(100, sym_aux_make(0, 0)) == 0,
          "ppid 0 -> no fallback");
    CHECK(sym_fallback_pid(100, sym_aux_make(1, 0)) == 0,
          "reparented to init -> no fallback");
    CHECK(sym_fallback_pid(100, sym_aux_make(100, 0)) == 0,
          "ppid == pid -> no fallback");
    CHECK(sym_fallback_pid(100, 0) == 0,
          "unknown aux -> no fallback");

    // Fixture: cache miss (the child's maps are gone and it never held a
    // snapshot, so nothing of its own can name the frame).
    CHECK(sym_fallback_wanted(1, 0) == 1,
          "gone without a snapshot -> fallback wanted");
    CHECK(sym_fallback_wanted(0, 0) == 0,
          "alive -> fallback not wanted");
    CHECK(sym_fallback_wanted(1, 5) == 0,
          "gone with a retained snapshot -> fallback not wanted");
    CHECK(sym_fallback_wanted(0, 5) == 0,
          "alive with a snapshot -> fallback not wanted");

    // A stack snapshot is unwound through the parent only when the stack
    // predates an exec.
    CHECK(sym_snapshot_parent(sym_aux_make(50, 1)) == 1,
          "exec stack -> unwind against the parent");
    CHECK(sym_snapshot_parent(sym_aux_make(50, 0)) == 0,
          "non-exec stack -> unwind against the child");
    CHECK(sym_snapshot_parent(sym_aux_make(0, 1)) == 0,
          "exec without a usable parent -> own pid");
    CHECK(sym_snapshot_parent(sym_aux_make(1, 1)) == 0,
          "exec reparented to init -> own pid");
    CHECK(sym_snapshot_parent(0) == 0,
          "unknown aux -> own pid");

    // An empty read keeps the last known snapshot only when there was one.
    CHECK(sym_maps_discard_read(5, 0) == 1,
          "empty read over a snapshot -> discard the read");
    CHECK(sym_maps_discard_read(5, 3) == 0,
          "non-empty read over a snapshot -> install it");
    CHECK(sym_maps_discard_read(0, 0) == 0,
          "empty read without a snapshot -> nothing to keep");
    CHECK(sym_maps_discard_read(0, 3) == 0,
          "first non-empty read -> install it");

    // The parent lookup matters only for exec events and for a process's
    // single-threaded pre-exec phase, where tid == tgid.
    // Fixture: single-threaded fork child.
    CHECK(sym_aux_wanted(0, 100, 100) == 1,
          "leader thread -> parent read wanted");
    CHECK(sym_aux_wanted(0, 100, 101) == 0,
          "non-leader thread -> parent read skipped");
    CHECK(sym_aux_wanted(1, 100, 101) == 1,
          "exec from any thread -> parent read wanted");

    // Parent tgid memory: a leader or exec event records the parent tgid, so a
    // later event of the same pid without aux still resolves against it.
    static struct sym_ppidc pc;
    __u32 got;

    CHECK(sym_ppidc_resolve(&pc, 100, 0) == 0,
          "empty parent table -> unknown stays unknown");
    CHECK(sym_ppidc_resolve(&pc, 100, sym_aux_make(50, 0)) == sym_aux_make(50, 0),
          "leader event passes through and is remembered");
    // Fixture: non-leader thread (aux 0 filled from the table).
    got = sym_ppidc_resolve(&pc, 100, 0);
    CHECK(got == sym_aux_make(50, 0),
          "later aux-less event of the same pid gets the parent");
    CHECK(sym_first_pid(100, got) == 100,
          "alive child stays on its own pid");
    CHECK(sym_fallback_pid(100, got) == 50,
          "remembered parent is available as fallback");
    CHECK(sym_fallback_wanted(1, 0) == 1,
          "gone child without a snapshot uses the remembered parent");
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

    // Fixture: pid reuse (ppid changes -> table updated).
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
