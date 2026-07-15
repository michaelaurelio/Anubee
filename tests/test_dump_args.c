// SPDX-License-Identifier: GPL-2.0
// Host check for dump's selector/trigger validation. dump.c includes
// dump.skel.h and cannot link host-side, so the rules live in a pure unit -
// same split as trace_args.c / tests/test_trace_args.c.
#include "dump/dump_args.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;
#define OK(t, msg) do { checks++;                                        \
    const char *e = dump_args_check(&(t));                               \
    if (e) { failures++; printf("  FAIL: %s (rejected: %s)\n", msg, e); }\
} while (0)
#define BAD(t, msg) do { checks++;                                       \
    const char *e = dump_args_check(&(t));                               \
    if (!e) { failures++; printf("  FAIL: %s (accepted)\n", msg); }      \
} while (0)

int main(void)
{
    // --- existing rules must keep behaving exactly as before ---
    struct dump_trigger both_targets = { .has_pkg = 1, .ntgt = 1, .npat = 1 };
    BAD(both_targets, "-p and -P are mutually exclusive");

    struct dump_trigger no_target = { .npat = 1 };
    BAD(no_target, "neither -p nor -P");

    struct dump_trigger no_selector = { .has_pkg = 1 };
    BAD(no_selector, "no pattern and no base");

    struct dump_trigger pkg_pat = { .has_pkg = 1, .npat = 1 };
    OK(pkg_pat, "-P with a pattern (the pre-existing happy path)");

    struct dump_trigger pid_pat = { .ntgt = 1, .npat = 1 };
    OK(pid_pat, "-p with a pattern");

    // --- --base satisfies the selector requirement on its own ---
    struct dump_trigger base_only = { .ntgt = 1, .nbase = 1 };
    OK(base_only, "--base alone satisfies the selector requirement");

    struct dump_trigger base_and_pat = { .ntgt = 1, .npat = 1, .nbase = 1 };
    OK(base_and_pat, "--base and -l together are an OR, not a conflict");

    // --- --now requires -p and forbids -P ---
    struct dump_trigger now_pid = { .now = 1, .ntgt = 1, .nbase = 1 };
    OK(now_pid, "--now with -p");

    struct dump_trigger now_pkg = { .now = 1, .has_pkg = 1, .npat = 1 };
    BAD(now_pkg, "--now with -P is rejected (-P launches; 'now' is meaningless)");

    // --- --now and --on-map are mutually exclusive triggers ---
    struct dump_trigger now_onmap = { .now = 1, .on_map = 1, .ntgt = 1, .npat = 1 };
    BAD(now_onmap, "--now with --on-map is rejected");

    // --- --check requires --now ---
    // dump_run's on-exit path writes .so files and does not consult g_check, so
    // `--check` without `--now` would silently dump instead of comparing. Reject
    // it at parse time rather than surprise the caller with the wrong artifact.
    struct dump_trigger check_now = { .now = 1, .check = 1, .ntgt = 1, .nbase = 1 };
    OK(check_now, "--check with --now");

    struct dump_trigger check_alone = { .check = 1, .has_pkg = 1, .npat = 1 };
    BAD(check_alone, "--check without --now is rejected");

    struct dump_trigger check_onmap = { .check = 1, .on_map = 1, .ntgt = 1, .npat = 1 };
    BAD(check_onmap, "--check with --on-map (but no --now) is rejected");

    // --- --on-map keeps working unchanged ---
    struct dump_trigger onmap = { .on_map = 1, .has_pkg = 1, .npat = 1 };
    OK(onmap, "--on-map with -P still valid");

    // --- dump_parse_base ---------------------------------------------------
    // A --base that silently parses wrong defeats the flag's whole purpose:
    // selecting by address is what resists per-run library renaming.
    unsigned long long b = 0;

    checks++;
    if (dump_parse_base("0x7281a0000", &b) != 0 || b != 0x7281a0000ULL) {
        failures++; printf("  FAIL: hex base parses\n");
    }
    checks++;
    if (dump_parse_base("4096", &b) != 0 || b != 4096ULL) {
        failures++; printf("  FAIL: decimal base parses\n");
    }
    // strtoull WRAPS a negative to ULLONG_MAX with errno unset and end at the
    // NUL, so every after-the-fact check passes. This is the regression.
    checks++;
    if (dump_parse_base("-1", &b) == 0) {
        failures++; printf("  FAIL: -1 must be rejected, not wrapped to ULLONG_MAX\n");
    }
    checks++;
    if (dump_parse_base("+1", &b) == 0) {
        failures++; printf("  FAIL: +1 must be rejected\n");
    }
    // strtoull skips leading whitespace per the C standard.
    checks++;
    if (dump_parse_base(" 0x1000", &b) == 0) {
        failures++; printf("  FAIL: leading whitespace must be rejected\n");
    }
    checks++;
    if (dump_parse_base("0x1000junk", &b) == 0) {
        failures++; printf("  FAIL: trailing junk must be rejected\n");
    }
    checks++;
    if (dump_parse_base("0x", &b) == 0) {
        failures++; printf("  FAIL: bare 0x must be rejected\n");
    }
    checks++;
    if (dump_parse_base("", &b) == 0) {
        failures++; printf("  FAIL: empty must be rejected\n");
    }
    // 17 hex digits: strtoull returns ULLONG_MAX and sets ERANGE.
    checks++;
    if (dump_parse_base("0xFFFFFFFFFFFFFFFFF", &b) == 0) {
        failures++; printf("  FAIL: overflow must be rejected (ERANGE)\n");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
