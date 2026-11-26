// SPDX-License-Identifier: GPL-2.0
// Host unit test for the /proc/<pid>/maps line parser: device and inode fields
// between the offset and the path.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "common/maps.h"

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

static void test_parse_inode_dev(void)
{
    struct anubee_map_line m;

    CHECK(anubee_parse_maps_line(
        "7f0000-7f1000 r-xp 00002000 fd:01 123456 /system/lib64/libc.so\n",
        &m) == 1, "file: returns 1");
    CHECK(m.start == 0x7f0000, "file: start");
    CHECK(m.end == 0x7f1000, "file: end");
    CHECK(m.off == 0x2000, "file: off");
    CHECK(m.exec == 1, "file: exec");
    CHECK(m.inode == 123456, "file: inode");
    CHECK(m.dev == ((0xfdU << 20) | 0x01U), "file: dev");
    CHECK(strcmp(m.path, "/system/lib64/libc.so") == 0, "file: path");
    CHECK(m.id == 0, "file: id");
    CHECK(m.add_seq == 0, "file: add_seq");
    CHECK(m.del_seq == 0, "file: del_seq");

    CHECK(anubee_parse_maps_line(
        "7f2000-7f3000 rw-p 00000000 00:00 0\n",
        &m) == 1, "anon: returns 1");
    CHECK(m.exec == 0, "anon: not exec");
    CHECK(m.inode == 0, "anon: inode");
    CHECK(m.dev == 0, "anon: dev");
    CHECK(m.path[0] == '\0', "anon: empty path");

    CHECK(anubee_parse_maps_line(
        "7f4000-7f5000 r--p 00000000 103:2a 99 /data/app/x/base.apk\n",
        &m) == 1, "apk: returns 1");
    CHECK(m.dev == ((0x103U << 20) | 0x2aU), "apk: dev");
    CHECK(m.inode == 99, "apk: inode");
    CHECK(strcmp(m.path, "/data/app/x/base.apk") == 0, "apk: path");

    CHECK(anubee_parse_maps_line(
        "7f6000-7f7000 r-xp 00000000 fd:01 5 /memfd:jit cache (deleted)\n",
        &m) == 1, "spaces: returns 1");
    CHECK(strcmp(m.path, "/memfd:jit cache (deleted)") == 0, "spaces: full path");

    CHECK(anubee_parse_maps_line("hello\n", &m) == 0, "garbage: returns 0");
}

int main(void)
{
    test_parse_inode_dev();

    if (fails) { printf("FAILED: %d check(s)\n", fails); return 1; }
    printf("test_maps_parse: all checks passed\n");
    return 0;
}
