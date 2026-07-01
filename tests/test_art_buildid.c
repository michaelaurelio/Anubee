// SPDX-License-Identifier: GPL-2.0
// Host unit test for the ART BuildID -> offsets gate (pure table lookup).
#include "common/art_buildid.h"
#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } } while (0)

int main(void)
{
    const struct art_offsets *o = art_offsets_for_buildid("1f156fc62660d075a8d675db850b95d5");
    CHECK(o != NULL, "known BuildID resolves offsets");
    if (o) {
        CHECK(o->managed_stack == 0xA8, "managed_stack offset");
        CHECK(o->ms_top_shadow == 0x10, "top_shadow_frame_ offset");
        CHECK(o->sf_method == 0x08, "ShadowFrame.method_ offset");
        CHECK(o->sf_dex_pc_ptr == 0x18, "ShadowFrame.dex_pc_ptr_ offset");
    }
    CHECK(art_offsets_for_buildid("deadbeef") == NULL, "unknown BuildID -> NULL (gate off)");
    CHECK(art_offsets_for_buildid(NULL) == NULL, "NULL BuildID -> NULL");

    printf("test_art_buildid: %s (%d checks, %d failures)\n",
           failures ? "FAIL" : "ok", checks, failures);
    return failures ? 1 : 0;
}
