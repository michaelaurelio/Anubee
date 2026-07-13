// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit test for dump/rebuild.c's dump_name_matches_any — the
// OR-of-dump_name_matches multi-pattern predicate used by dump-on-map/exit.
#include "dump/rebuild.h"

#include <stdio.h>

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                         \
    checks++;                                         \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    const char *pats[] = { "libA*", "libsecret*" };

    CHECK(dump_name_matches_any(pats, 2, "/x/libsecret.so") == 1,
          "any: 2nd pattern hits");
    CHECK(dump_name_matches_any(pats, 2, "/x/libAfoo.so") == 1,
          "any: 1st pattern hits");
    CHECK(dump_name_matches_any(pats, 2, "/x/libz.so") == 0,
          "any: neither hits");
    CHECK(dump_name_matches_any(pats, 1, "/x/libAfoo.so") == 1,
          "any: npat==1 matches legacy single-pattern predicate");

    // Substring mode: pattern with no glob metachars matches by
    // substring-of-fullpath, mirroring dump_name_matches's own behavior.
    const char *substr_pats[] = { "secret" };
    CHECK(dump_name_matches_any(substr_pats, 1, "/data/app/libsecret.so") == 1,
          "any: substring-of-fullpath match");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
