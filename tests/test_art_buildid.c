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
    CHECK(o != NULL, "known BuildID -> offsets");
    /* ShadowFrame family */
    CHECK(o && o->tls_thread_slot == 0x38, "tls_thread_slot 0x38");
    CHECK(o && o->managed_stack   == 0xA8, "managed_stack 0xA8");
    CHECK(o && o->sf_method       == 0x08, "sf_method 0x08");
    CHECK(o && o->sf_dex_pc_ptr   == 0x18, "sf_dex_pc_ptr 0x18");
    /* nterp family (newly unified into the row) */
    CHECK(o && o->artm_declclass   == 0x00, "artm_declclass 0x00");
    CHECK(o && o->artm_dexidx      == 0x08, "artm_dexidx 0x08");
    CHECK(o && o->class_dexcache   == 0x10, "class_dexcache 0x10");
    CHECK(o && o->dexcache_dexfile == 0x10, "dexcache_dexfile 0x10");
    CHECK(o && o->dexfile_begin    == 0x08, "dexfile_begin 0x08");
    CHECK(o && o->dexfile_datasize == 0x20, "dexfile_datasize 0x20");
    CHECK(art_offsets_for_buildid("deadbeef") == NULL, "unknown BuildID -> NULL (gate off)");
    CHECK(art_offsets_for_buildid(NULL) == NULL, "NULL BuildID -> NULL");
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
