// SPDX-License-Identifier: GPL-2.0
// Host unit tests for src/common/maps.c (no BPF required).
// Tests: anubee_parse_maps_line — field values, exec flag, anonymous/special
// mappings, paths with embedded spaces, (deleted) suffix, APK path, malformed.
// Also: anubee_module_base_idx, anubee_map_files_path.
#include "common/maps.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    struct anubee_map_line m;

    // Normal executable mapping
    CHECK(anubee_parse_maps_line(
        "7b4a200000-7b4a210000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so\n",
        &m) == 1, "normal: returns 1");
    CHECK(m.start == 0x7b4a200000ULL, "normal: start");
    CHECK(m.end   == 0x7b4a210000ULL, "normal: end");
    CHECK(m.off   == 0,               "normal: off");
    CHECK(m.exec  == 1,               "normal: exec");
    CHECK(strcmp(m.path, "/system/lib64/libc.so") == 0, "normal: path");

    // Non-executable mapping
    CHECK(anubee_parse_maps_line(
        "7b4a210000-7b4a220000 rw-p 00010000 fd:00 12345 /system/lib64/libc.so\n",
        &m) == 1, "rw: returns 1");
    CHECK(m.exec == 0, "rw: not exec");

    // Anonymous mapping (no path)
    CHECK(anubee_parse_maps_line(
        "7fff100000-7fff200000 rw-p 00000000 00:00 0 \n",
        &m) == 1, "anon: returns 1");
    CHECK(m.path[0] == '\0', "anon: empty path");

    // Special mapping like [stack] or [anon:...]
    CHECK(anubee_parse_maps_line(
        "7fff200000-7fff300000 rw-p 00000000 00:00 0 [stack]\n",
        &m) == 1, "special: returns 1");
    CHECK(strcmp(m.path, "[stack]") == 0, "special: path");

    // Non-zero file offset (APK-embedded .so)
    CHECK(anubee_parse_maps_line(
        "7b3c000000-7b3c100000 r-xp 00041000 fd:01 99 /data/app/com.example/base.apk\n",
        &m) == 1, "apk: returns 1");
    CHECK(m.off == 0x41000ULL, "apk: offset");
    CHECK(strcmp(m.path, "/data/app/com.example/base.apk") == 0, "apk: path");

    // (deleted) suffix is kept verbatim in the path field
    CHECK(anubee_parse_maps_line(
        "7b1a000000-7b1a010000 r-xp 00000000 fd:00 5 /system/lib64/libfoo.so (deleted)\n",
        &m) == 1, "deleted: returns 1");
    CHECK(strstr(m.path, "(deleted)") != NULL, "deleted: suffix in path");

    // Malformed line (only 3 fields) — must return 0 (skip)
    CHECK(anubee_parse_maps_line(
        "7b0000-7b1000 r-xp\n",
        &m) == 0, "malformed: returns 0");

    // Entirely empty line
    CHECK(anubee_parse_maps_line("\n", &m) == 0, "empty: returns 0");

    // Path with embedded spaces — full path must survive (regression guard for
    // the two stale sscanf copies that used %255s and would truncate here).
    CHECK(anubee_parse_maps_line(
        "7b5a000000-7b5a010000 r-xp 00000000 fd:00 7 /data/app/My App/lib/libfoo.so\n",
        &m) == 1, "spaces: returns 1");
    CHECK(strcmp(m.path, "/data/app/My App/lib/libfoo.so") == 0, "spaces: full path");

    // anubee_module_base_idx: a 3-entry contiguous same-path run → base is index 0.
    struct anubee_map_line seg[4];
    seg[0].start = 0x1000; seg[0].end = 0x2000; seg[0].off = 0;
    snprintf(seg[0].path, sizeof(seg[0].path), "/lib/foo.so");
    seg[1].start = 0x2000; seg[1].end = 0x3000; seg[1].off = 0x1000;
    snprintf(seg[1].path, sizeof(seg[1].path), "/lib/foo.so");
    seg[2].start = 0x3000; seg[2].end = 0x4000; seg[2].off = 0x2000;
    snprintf(seg[2].path, sizeof(seg[2].path), "/lib/foo.so");
    seg[3].start = 0x4000; seg[3].end = 0x5000; seg[3].off = 0;
    snprintf(seg[3].path, sizeof(seg[3].path), "/lib/bar.so");  // different lib stops walk
    CHECK(anubee_module_base_idx(seg, 2) == 0, "base_idx: run of 3 → base is 0");
    CHECK(anubee_module_base_idx(seg, 3) == 3, "base_idx: path boundary stops walk");
    CHECK(anubee_module_base_idx(seg, 0) == 0, "base_idx: hit==0 never underflows");

    // --- CFI-misstep regression cases (gapped multi-PT_LOAD) ---

    // Case 1: gapped libandroid_runtime layout — RO off 0, exec off 0xe0000 with a
    // 1-page ADDRESS GAP (end != start). Walk-back must bridge the gap to the RO base.
    struct anubee_map_line lar[2];
    lar[0].start = 0xb15000; lar[0].end = 0xbf4000; lar[0].off = 0;
    snprintf(lar[0].path, sizeof(lar[0].path), "/system/lib64/libandroid_runtime.so");
    lar[1].start = 0xbf5000; lar[1].end = 0xd87000; lar[1].off = 0xe0000;   // gap before
    snprintf(lar[1].path, sizeof(lar[1].path), "/system/lib64/libandroid_runtime.so");
    CHECK(anubee_module_base_idx(lar, 1) == 0, "base_idx: gapped lib walks back to off-0 base");

    // Case 2: contiguous lib (libc-style) — no regression, still resolves to index 0.
    struct anubee_map_line libc[2];
    libc[0].start = 0x100000; libc[0].end = 0x1de000; libc[0].off = 0;
    snprintf(libc[0].path, sizeof(libc[0].path), "/system/lib64/libc.so");
    libc[1].start = 0x1de000; libc[1].end = 0x2c0000; libc[1].off = 0xde000;  // contiguous
    snprintf(libc[1].path, sizeof(libc[1].path), "/system/lib64/libc.so");
    CHECK(anubee_module_base_idx(libc, 1) == 0, "base_idx: contiguous lib still base 0");

    // Case 3: two DISTINCT same-path loads (offset resets to 0 at load B). Walk-back
    // from B's exec must stop at B's RO base, NOT merge into load A.
    struct anubee_map_line two[4];
    two[0].start = 0x10000; two[0].end = 0x20000; two[0].off = 0;        // A RO
    two[1].start = 0x20000; two[1].end = 0x30000; two[1].off = 0xe0000;  // A EXEC
    two[2].start = 0x30000; two[2].end = 0x40000; two[2].off = 0;        // B RO  (reset)
    two[3].start = 0x40000; two[3].end = 0x50000; two[3].off = 0xe0000;  // B EXEC
    for (int k = 0; k < 4; k++)
        snprintf(two[k].path, sizeof(two[k].path), "/system/lib64/libfoo.so");
    CHECK(anubee_module_base_idx(two, 3) == 2, "base_idx: distinct re-load not merged");

    // Case 4: single APK-embedded lib, GAPPED, lowest off 0x41000 (no off==0 segment).
    // Walk-back must reach the lowest-offset mapping, not strand at the exec segment.
    struct anubee_map_line apk1[2];
    apk1[0].start = 0x100000; apk1[0].end = 0x150000; apk1[0].off = 0x41000;
    snprintf(apk1[0].path, sizeof(apk1[0].path), "/data/app/com.example/base.apk");
    apk1[1].start = 0x151000; apk1[1].end = 0x160000; apk1[1].off = 0x52000;  // gap
    snprintf(apk1[1].path, sizeof(apk1[1].path), "/data/app/com.example/base.apk");
    CHECK(anubee_module_base_idx(apk1, 1) == 0, "base_idx: single APK lib not stranded");

    // Case 5: KNOWN-LIMITATION guard — 2+ uncompressed libs in one APK share the bare
    // APK path and have monotonic offsets with no reset. The guard CANNOT separate them;
    // bar merges into foo's base. Asserts the CURRENT (documented) behavior; flip if
    // same-APK separation is ever implemented.
    struct anubee_map_line apk2[4];
    apk2[0].start = 0x100000; apk2[0].end = 0x110000; apk2[0].off = 0x41000;  // foo RO
    apk2[1].start = 0x110000; apk2[1].end = 0x120000; apk2[1].off = 0x42000;  // foo EXEC
    apk2[2].start = 0x120000; apk2[2].end = 0x130000; apk2[2].off = 0x60000;  // bar RO
    apk2[3].start = 0x130000; apk2[3].end = 0x140000; apk2[3].off = 0x61000;  // bar EXEC
    for (int k = 0; k < 4; k++)
        snprintf(apk2[k].path, sizeof(apk2[k].path), "/data/app/com.example/base.apk");
    CHECK(anubee_module_base_idx(apk2, 3) == 0, "base_idx: same-APK multi-lib merges (known limit)");

    // --- Part 2: filler-mapping skip (the on-device [page size compat] root cause) ---

    // Case 6: [page size compat] guard mapping (different path) between RO and exec.
    // The walk must SKIP the guard and collapse to the off-0 RO base. Reproduces the
    // exact on-device libandroid_runtime layout that defeated Task 1's fix.
    struct anubee_map_line pgc[3];
    pgc[0].start = 0xb15000; pgc[0].end = 0xbf4000; pgc[0].off = 0;
    snprintf(pgc[0].path, sizeof(pgc[0].path), "/system/lib64/libandroid_runtime.so");
    pgc[1].start = 0xbf4000; pgc[1].end = 0xbf5000; pgc[1].off = 0;
    snprintf(pgc[1].path, sizeof(pgc[1].path), "[page size compat]");
    pgc[2].start = 0xbf5000; pgc[2].end = 0xd87000; pgc[2].off = 0xe0000;
    snprintf(pgc[2].path, sizeof(pgc[2].path), "/system/lib64/libandroid_runtime.so");
    CHECK(anubee_module_base_idx(pgc, 2) == 0, "base_idx: skips [page size compat] guard");

    // Case 7: anonymous (empty-path) filler between segments is skipped too.
    struct anubee_map_line anon[3];
    anon[0].start = 0x100000; anon[0].end = 0x110000; anon[0].off = 0;
    snprintf(anon[0].path, sizeof(anon[0].path), "/system/lib64/libfoo.so");
    anon[1].start = 0x110000; anon[1].end = 0x111000; anon[1].off = 0;
    anon[1].path[0] = '\0';                                   // empty-path anon filler
    anon[2].start = 0x111000; anon[2].end = 0x200000; anon[2].off = 0xe0000;
    snprintf(anon[2].path, sizeof(anon[2].path), "/system/lib64/libfoo.so");
    CHECK(anubee_module_base_idx(anon, 2) == 0, "base_idx: skips empty-path anon filler");

    // Case 8: a filler does NOT cause a merge into a DIFFERENT real file. With other.so
    // (different path) before the filler, the walk breaks and returns the exec index
    // itself — never merging libfoo into other.so.
    struct anubee_map_line mix[3];
    mix[0].start = 0x100000; mix[0].end = 0x110000; mix[0].off = 0;
    snprintf(mix[0].path, sizeof(mix[0].path), "/system/lib64/other.so");
    mix[1].start = 0x110000; mix[1].end = 0x111000; mix[1].off = 0;
    snprintf(mix[1].path, sizeof(mix[1].path), "[page size compat]");
    mix[2].start = 0x111000; mix[2].end = 0x200000; mix[2].off = 0xe0000;
    snprintf(mix[2].path, sizeof(mix[2].path), "/system/lib64/libfoo.so");
    CHECK(anubee_module_base_idx(mix, 2) == 2, "base_idx: filler does not merge unrelated files");

    // anubee_map_files_path: check the format string.
    char mfbuf[96];
    anubee_map_files_path(mfbuf, sizeof(mfbuf), 1234, 0x7b4a200000ULL, 0x7b4a210000ULL);
    CHECK(strcmp(mfbuf, "/proc/1234/map_files/7b4a200000-7b4a210000") == 0,
          "map_files_path: correct format");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
