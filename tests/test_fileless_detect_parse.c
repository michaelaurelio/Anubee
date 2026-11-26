// SPDX-License-Identifier: GPL-2.0
// Host unit tests for fileless-detect's pure helpers: finding the mapping that
// holds an address in /proc/<pid>/maps (and its kernel-side name), deciding
// whether a region name is ART's own, and classifying region content.
#include <stdio.h>
#include <string.h>
#include "modules/fileless_detect_parse.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

// Shapes taken from a real Android 16 app's maps.
static const char *MAPS =
    "4d059000-4f059000 r-xs 02000000 00:01 3174                               [anon_shmem:dalvik-zygote-jit-code-cache]\n"
    "51059000-53059000 r-xs 02000000 00:01 71436                              [anon_shmem:dalvik-jit-code-cache]\n"
    "7000000000-7000001000 rwxp 00000000 00:00 0 \n"
    "7000002000-7000003000 r-xp 00000000 00:00 0                              [anon:payload]\n"
    "7000004000-7000006000 r-xs 00000000 00:01 4242                           /memfd:stage2 (deleted)\n"
    "7672f4b000-7673103000 r-xp 00098000 fe:53 34644                          /data/dalvik-cache/arm64/x.dex\n";

int main(void)
{
    unsigned long s = 0, e = 0;
    char perms[8], name[128];

    CHECK(fl_maps_region(MAPS, 0x51060000UL, &s, &e, perms, name, sizeof name) == 1,
          "address inside the JIT cache found");
    CHECK(s == 0x51059000UL && e == 0x53059000UL, "region bounds");
    CHECK(strcmp(perms, "r-xs") == 0, "perms");
    CHECK(strcmp(name, "dalvik-jit-code-cache") == 0, "[anon_shmem:...] name stripped");
    CHECK(fl_name_is_art(name), "dalvik- name is ART");

    CHECK(fl_maps_region(MAPS, 0x7000000800UL, &s, &e, perms, name, sizeof name) == 1,
          "unnamed anonymous region found");
    CHECK(name[0] == '\0', "unnamed region has empty name");
    CHECK(!fl_name_is_art(name), "unnamed region is not ART");

    CHECK(fl_maps_region(MAPS, 0x7000002000UL, &s, &e, perms, name, sizeof name) == 1 &&
          strcmp(name, "payload") == 0, "[anon:...] name stripped");
    CHECK(!fl_name_is_art(name), "other anon name is not ART");

    CHECK(fl_maps_region(MAPS, 0x7000005000UL, &s, &e, perms, name, sizeof name) == 1 &&
          strcmp(name, "/memfd:stage2 (deleted)") == 0, "file-backed name kept as path");

    CHECK(fl_maps_region(MAPS, 0x7000001800UL, &s, &e, perms, name, sizeof name) == 0,
          "address in a gap not found");
    CHECK(fl_maps_region(NULL, 0x1000, &s, &e, perms, name, sizeof name) == 0, "NULL maps");

    // ART's memfd-backed JIT cache (when memfd is available) and its names.
    CHECK(fl_name_is_art("memfd:jit-cache"), "memfd jit-cache is ART");
    CHECK(fl_name_is_art("memfd:jit-zygote-cache"), "memfd jit-zygote-cache is ART");
    CHECK(fl_name_is_art("/memfd:jit-cache (deleted)"), "maps form of the memfd name is ART");
    CHECK(!fl_name_is_art("memfd:stage2"), "other memfd is not ART");
    CHECK(!fl_name_is_art(NULL), "NULL is not ART");

    // ---- content classification ---------------------------------------------
    const unsigned char elf[16] = { 0x7f, 'E', 'L', 'F', 2, 1, 1 };
    const unsigned char zero[16] = { 0 };
    const unsigned char code[16] = { 0xfd, 0x7b, 0xbf, 0xa9 };   // arm64 stp x29, x30
    CHECK(strcmp(fl_content_of(elf, sizeof elf), "elf") == 0, "elf content");
    CHECK(strcmp(fl_content_of(zero, sizeof zero), "zero") == 0, "all-zero content");
    CHECK(strcmp(fl_content_of(code, sizeof code), "data") == 0, "other content");
    CHECK(fl_content_of(NULL, 0) == NULL, "nothing read -> NULL");

    CHECK(strcmp(fl_kind_name(FL_KIND_ANON_MMAP), "anon_exec_mmap") == 0, "kind anon");
    CHECK(strcmp(fl_kind_name(FL_KIND_MPROTECT_EXEC), "mprotect_exec") == 0, "kind mprotect");
    CHECK(strcmp(fl_kind_name(FL_KIND_MEMFD_EXEC), "memfd_exec") == 0, "kind memfd");
    CHECK(strcmp(fl_kind_name(42), "unknown") == 0, "kind out of range");

    printf("test_fileless_detect_parse: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
