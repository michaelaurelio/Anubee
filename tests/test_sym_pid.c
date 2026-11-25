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

    if (fails) { printf("FAILED: %d check(s)\n", fails); return 1; }
    printf("test_sym_pid: all checks passed\n");
    return 0;
}
