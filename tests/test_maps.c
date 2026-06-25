// SPDX-License-Identifier: GPL-2.0
// Host unit tests for src/common/maps.c (no BPF required).
// Tests: ares_parse_maps_line — field values, exec flag, anonymous/special
// mappings, paths with embedded spaces, (deleted) suffix, APK path, malformed.
// Also: ares_module_base_idx, ares_map_files_path.
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
    struct ares_map_line m;

    // Normal executable mapping
    CHECK(ares_parse_maps_line(
        "7b4a200000-7b4a210000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so\n",
        &m) == 1, "normal: returns 1");
    CHECK(m.start == 0x7b4a200000ULL, "normal: start");
    CHECK(m.end   == 0x7b4a210000ULL, "normal: end");
    CHECK(m.off   == 0,               "normal: off");
    CHECK(m.exec  == 1,               "normal: exec");
    CHECK(strcmp(m.path, "/system/lib64/libc.so") == 0, "normal: path");

    // Non-executable mapping
    CHECK(ares_parse_maps_line(
        "7b4a210000-7b4a220000 rw-p 00010000 fd:00 12345 /system/lib64/libc.so\n",
        &m) == 1, "rw: returns 1");
    CHECK(m.exec == 0, "rw: not exec");

    // Anonymous mapping (no path)
    CHECK(ares_parse_maps_line(
        "7fff100000-7fff200000 rw-p 00000000 00:00 0 \n",
        &m) == 1, "anon: returns 1");
    CHECK(m.path[0] == '\0', "anon: empty path");

    // Special mapping like [stack] or [anon:...]
    CHECK(ares_parse_maps_line(
        "7fff200000-7fff300000 rw-p 00000000 00:00 0 [stack]\n",
        &m) == 1, "special: returns 1");
    CHECK(strcmp(m.path, "[stack]") == 0, "special: path");

    // Non-zero file offset (APK-embedded .so)
    CHECK(ares_parse_maps_line(
        "7b3c000000-7b3c100000 r-xp 00041000 fd:01 99 /data/app/com.example/base.apk\n",
        &m) == 1, "apk: returns 1");
    CHECK(m.off == 0x41000ULL, "apk: offset");
    CHECK(strcmp(m.path, "/data/app/com.example/base.apk") == 0, "apk: path");

    // (deleted) suffix is kept verbatim in the path field
    CHECK(ares_parse_maps_line(
        "7b1a000000-7b1a010000 r-xp 00000000 fd:00 5 /system/lib64/libfoo.so (deleted)\n",
        &m) == 1, "deleted: returns 1");
    CHECK(strstr(m.path, "(deleted)") != NULL, "deleted: suffix in path");

    // Malformed line (only 3 fields) — must return 0 (skip)
    CHECK(ares_parse_maps_line(
        "7b0000-7b1000 r-xp\n",
        &m) == 0, "malformed: returns 0");

    // Entirely empty line
    CHECK(ares_parse_maps_line("\n", &m) == 0, "empty: returns 0");

    // Path with embedded spaces — full path must survive (regression guard for
    // the two stale sscanf copies that used %255s and would truncate here).
    CHECK(ares_parse_maps_line(
        "7b5a000000-7b5a010000 r-xp 00000000 fd:00 7 /data/app/My App/lib/libfoo.so\n",
        &m) == 1, "spaces: returns 1");
    CHECK(strcmp(m.path, "/data/app/My App/lib/libfoo.so") == 0, "spaces: full path");

    // ares_module_base_idx: a 3-entry contiguous same-path run → base is index 0.
    struct ares_map_line seg[4];
    seg[0].start = 0x1000; seg[0].end = 0x2000; seg[0].off = 0;
    snprintf(seg[0].path, sizeof(seg[0].path), "/lib/foo.so");
    seg[1].start = 0x2000; seg[1].end = 0x3000; seg[1].off = 0x1000;
    snprintf(seg[1].path, sizeof(seg[1].path), "/lib/foo.so");
    seg[2].start = 0x3000; seg[2].end = 0x4000; seg[2].off = 0x2000;
    snprintf(seg[2].path, sizeof(seg[2].path), "/lib/foo.so");
    seg[3].start = 0x4000; seg[3].end = 0x5000; seg[3].off = 0;
    snprintf(seg[3].path, sizeof(seg[3].path), "/lib/bar.so");  // different lib stops walk
    CHECK(ares_module_base_idx(seg, 2) == 0, "base_idx: run of 3 → base is 0");
    CHECK(ares_module_base_idx(seg, 3) == 3, "base_idx: path boundary stops walk");
    CHECK(ares_module_base_idx(seg, 0) == 0, "base_idx: hit==0 never underflows");

    // ares_map_files_path: check the format string.
    char mfbuf[96];
    ares_map_files_path(mfbuf, sizeof(mfbuf), 1234, 0x7b4a200000ULL, 0x7b4a210000ULL);
    CHECK(strcmp(mfbuf, "/proc/1234/map_files/7b4a200000-7b4a210000") == 0,
          "map_files_path: correct format");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
