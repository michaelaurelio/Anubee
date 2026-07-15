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

    // --- dump_sel_matches: patterns OR exact bases ---------------------------
    // A base selector ignores the path entirely: this is what makes a
    // randomized/renamed/(deleted) library name irrelevant - we select the
    // module we observed, not a name we guessed.
    const unsigned long long bases[] = { 0x7281a0000ULL, 0xb0ULL };
    struct dump_sel base_only = { .bases = bases, .nbase = 2 };
    CHECK(dump_sel_matches(&base_only, "/anything/at/all.so", 0x7281a0000ULL) == 1,
          "base selector matches exact base");
    CHECK(dump_sel_matches(&base_only, "/anything/at/all.so", 0xb0ULL) == 1,
          "base selector matches second base");
    CHECK(dump_sel_matches(&base_only, "/anything/at/all.so", 0x7281a0001ULL) == 0,
          "base selector is exact, not a range");

    // A pattern selector ignores the base.
    const char *sel_pats[] = { "libsentinel.so" };
    struct dump_sel pat_only = { .pats = sel_pats, .npat = 1 };
    CHECK(dump_sel_matches(&pat_only, "/lib/libsentinel.so", 0x1ULL) == 1,
          "pattern selector matches path");
    CHECK(dump_sel_matches(&pat_only, "/lib/libother.so", 0x1ULL) == 0,
          "pattern selector rejects non-match");

    // Both present = OR, not AND.
    struct dump_sel both = { .pats = sel_pats, .npat = 1, .bases = bases, .nbase = 2 };
    CHECK(dump_sel_matches(&both, "/lib/libother.so", 0xb0ULL) == 1,
          "base hit alone is enough when both selectors are set");
    CHECK(dump_sel_matches(&both, "/lib/libsentinel.so", 0xdeadULL) == 1,
          "pattern hit alone is enough when both selectors are set");
    CHECK(dump_sel_matches(&both, "/lib/libother.so", 0xdeadULL) == 0,
          "neither hit -> no match");

    // An empty selector matches nothing (dump_args_check forbids it reaching here).
    struct dump_sel empty = { 0 };
    CHECK(dump_sel_matches(&empty, "/lib/libsentinel.so", 0xb0ULL) == 0,
          "empty selector matches nothing");

    // hit[] tracking still works through the selector.
    int hit[1] = { 0 };
    struct dump_sel tracked = { .pats = sel_pats, .npat = 1, .hit = hit };
    dump_sel_matches(&tracked, "/lib/libsentinel.so", 0x1ULL);
    CHECK(hit[0] == 1, "selector records pattern hit");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
