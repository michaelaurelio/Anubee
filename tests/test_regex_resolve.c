// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit tests for resolve_custom_spec_matches_for_path — the
// bulk /regex/-delimited function-name resolver added in EPIC H12 to replace
// -I/-i/-r. Uses a real ELF fixture (no device) so the regexec-against-real-
// symbols path is genuinely exercised, not just parsed.
#include "common/probe_resolve.h"

#include <libelf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int checks = 0, failures = 0;

static void noop_log(const char *fmt, ...) { (void)fmt; }

#define CHECK(cond, msg) do {                         \
    checks++;                                         \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static const char *fixture = "tests/fixtures/eh_frame_sample.so";

int main(void)
{
    elf_version(EV_CURRENT);   // required once before any elf_begin() call (libelf contract)

    custom_probe_spec_t spec;

    // --- two-symbol match: both *_tm_clones functions ---
    CHECK(parse_custom_probe_spec("libc.so!/_clones$/", &spec, noop_log) == 0,
          "parse: /_clones$/ spec");
    {
        probe_target_t out[8];
        int n = resolve_custom_spec_matches_for_path(getpid(), fixture, &spec, out, 8);
        CHECK(n == 2, "two-match: n == 2");
        bool saw_dereg = false, saw_reg = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(out[i].func_name, "deregister_tm_clones") == 0) saw_dereg = true;
            if (strcmp(out[i].func_name, "register_tm_clones") == 0) saw_reg = true;
            CHECK(strcmp(out[i].mod_path, fixture) == 0, "two-match: mod_path is the file path");
        }
        CHECK(saw_dereg && saw_reg, "two-match: both *_tm_clones symbols present");
    }

    // --- single-symbol match: only register_tm_clones (not deregister_) ---
    CHECK(parse_custom_probe_spec("libc.so!/^register_/", &spec, noop_log) == 0,
          "parse: /^register_/ spec");
    {
        probe_target_t out[8];
        int n = resolve_custom_spec_matches_for_path(getpid(), fixture, &spec, out, 8);
        CHECK(n == 1, "single-match: n == 1");
        CHECK(n == 1 && strcmp(out[0].func_name, "register_tm_clones") == 0,
              "single-match: correct symbol name");
    }

    // --- zero matches: valid ELF, pattern matches nothing (not an error) ---
    CHECK(parse_custom_probe_spec("libc.so!/^nomatch_xyz/", &spec, noop_log) == 0,
          "parse: /^nomatch_xyz/ spec");
    {
        probe_target_t out[8];
        int n = resolve_custom_spec_matches_for_path(getpid(), fixture, &spec, out, 8);
        CHECK(n == 0, "zero-match: n == 0, not -1 (file opened fine, nothing matched)");
    }

    // --- ret_only / arg fields propagate from the spec to every match ---
    CHECK(parse_custom_probe_spec("libc.so!/_clones$/>V", &spec, noop_log) == 0,
          "parse: /_clones$/>V (return-only) spec");
    {
        probe_target_t out[8];
        int n = resolve_custom_spec_matches_for_path(getpid(), fixture, &spec, out, 8);
        CHECK(n == 2, "ret_only propagation: n == 2");
        for (int i = 0; i < n; i++) {
            CHECK(out[i].ret_only == true, "ret_only propagation: ret_only true on every match");
            CHECK(out[i].ret_type == ARG_VAL, "ret_only propagation: ret_type ARG_VAL on every match");
        }
    }

    // --- max_out cap is honored ---
    CHECK(parse_custom_probe_spec("libc.so!/_clones$/", &spec, noop_log) == 0,
          "parse: /_clones$/ spec (cap test)");
    {
        probe_target_t out[1];
        int n = resolve_custom_spec_matches_for_path(getpid(), fixture, &spec, out, 1);
        CHECK(n == 1, "cap: stops at max_out (1) even though 2 symbols match");
    }

    // --- open failure: nonexistent file returns -1, not 0 ---
    CHECK(parse_custom_probe_spec("libc.so!/anything/", &spec, noop_log) == 0,
          "parse: /anything/ spec (open-fail test)");
    {
        probe_target_t out[8];
        int n = resolve_custom_spec_matches_for_path(getpid(), "tests/fixtures/does_not_exist.so",
                                                       &spec, out, 8);
        CHECK(n == -1, "open failure: returns -1, distinct from zero-match's 0");
    }

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
