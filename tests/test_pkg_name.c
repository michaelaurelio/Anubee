// SPDX-License-Identifier: GPL-2.0
// Host unit tests for anubee_pkg_name_ok. In -p mode the package name is read
// from the target's /proc/<pid>/cmdline -- text the traced (possibly
// malicious) process controls -- and analyzers interpolate it into root
// shell commands (dumpsys/appops). Only a well-formed Java package name may
// pass, so no shell metacharacter ever reaches /system/bin/sh.
#include <stdio.h>
#include "common/pkg_name.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    CHECK(anubee_pkg_name_ok("com.example.app"), "plain package");
    CHECK(anubee_pkg_name_ok("com.Example_2.app_x"), "digits/underscore/caps");
    CHECK(anubee_pkg_name_ok("android"), "single segment");
    CHECK(!anubee_pkg_name_ok("com.x;touch /data/local/tmp/p"), "';' and space rejected");
    CHECK(!anubee_pkg_name_ok("com.x$(id)"), "'$(' rejected");
    CHECK(!anubee_pkg_name_ok("com.x`id`"), "backtick rejected");
    CHECK(!anubee_pkg_name_ok("com.x|sh"), "pipe rejected");
    CHECK(!anubee_pkg_name_ok("com.x\nreboot"), "newline rejected");
    CHECK(!anubee_pkg_name_ok("-com.x"), "leading '-' (option injection) rejected");
    CHECK(!anubee_pkg_name_ok("com..x"), "empty segment rejected");
    CHECK(!anubee_pkg_name_ok("com.1x"), "segment starting with a digit rejected");
    CHECK(!anubee_pkg_name_ok(".com.x") && !anubee_pkg_name_ok("com.x."), "leading/trailing dot rejected");
    CHECK(!anubee_pkg_name_ok(""), "empty rejected");
    CHECK(!anubee_pkg_name_ok(NULL), "NULL rejected");
    char longname[300];
    for (int i = 0; i < 299; i++) longname[i] = 'a';
    longname[299] = 0;
    CHECK(!anubee_pkg_name_ok(longname), "over 255 chars rejected");

    printf("test_pkg_name: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
