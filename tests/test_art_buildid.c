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

    /* cecb684d - the OTA-swapped libart on the same POCO C85 / Android 15;
     * struct layout unchanged from 1f156fc6, so offsets are identical. */
    const struct art_offsets *o2 =
        art_offsets_for_buildid("cecb684d19b4f44ee3cbd66142c315f4");
    CHECK(o2 != NULL, "cecb684d BuildID -> offsets");
    CHECK(o2 && o2->tls_thread_slot == 0x38, "cecb684d tls_thread_slot 0x38");
    CHECK(o2 && o2->managed_stack   == 0xA8, "cecb684d managed_stack 0xA8");
    CHECK(o2 && o2->sf_method       == 0x08, "cecb684d sf_method 0x08");
    CHECK(o2 && o2->dexfile_datasize == 0x20, "cecb684d dexfile_datasize 0x20");

    /* art_offsets_parse — key=value override row parser */
    {
        const char *good =
            "# candidate row\n"
            "buildid=1f156fc62660d075a8d675db850b95d5\n"
            "tls_thread_slot=0x38\n  managed_stack = 0xA8 \n"
            "ms_link=0x08\nms_top_shadow=0x10\nsf_link=0x00\nsf_method=0x08\n"
            "sf_dex_pc_ptr=0x18\nartm_declclass=0x00\nartm_dexidx=0x08\n"
            "class_dexcache=0x10\ndexcache_dexfile=0x10\ndexfile_begin=0x08\n"
            "\ndexfile_datasize=0x20\n";
        char bid[64]; struct art_offsets ov;
        CHECK(art_offsets_parse(good, bid, sizeof bid, &ov) == 1,
              "parse: complete row -> 1");
        CHECK(strcmp(bid, "1f156fc62660d075a8d675db850b95d5") == 0, "parse: buildid captured");
        CHECK(ov.managed_stack == 0xA8 && ov.sf_method == 0x08 &&
              ov.dexfile_datasize == 0x20 && ov.artm_declclass == 0x00,
              "parse: offsets captured (whitespace/comments/blank lines tolerated)");

        const char *missing =   /* drop dexfile_datasize */
            "buildid=abc\ntls_thread_slot=0x38\nmanaged_stack=0xA8\nms_link=0x08\n"
            "ms_top_shadow=0x10\nsf_link=0x00\nsf_method=0x08\nsf_dex_pc_ptr=0x18\n"
            "artm_declclass=0x00\nartm_dexidx=0x08\nclass_dexcache=0x10\n"
            "dexcache_dexfile=0x10\ndexfile_begin=0x08\n";
        CHECK(art_offsets_parse(missing, bid, sizeof bid, &ov) == 0,
              "parse: missing offset -> 0");

        const char *unknown =
            "buildid=abc\nbogus_key=0x1\n";
        CHECK(art_offsets_parse(unknown, bid, sizeof bid, &ov) == 0,
              "parse: unknown key -> 0");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
