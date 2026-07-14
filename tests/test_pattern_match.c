// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit tests for common/pattern_match.{h,c} — the shared
// exact/substring/glob/regex primitive that retires the independently
// reimplemented matchers in lib_seed.h / rebuild.c / probe_resolve.c.
#include "common/pattern_match.h"

#include <stdio.h>

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                         \
    checks++;                                         \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // --- pm_is_glob: trigger chars standardized to "*?[" ---
    CHECK(pm_is_glob("libc.so") == false,        "is_glob: plain string");
    CHECK(pm_is_glob("*.so") == true,             "is_glob: '*'");
    CHECK(pm_is_glob("lib?.so") == true,          "is_glob: '?'");
    CHECK(pm_is_glob("lib[co].so") == true,       "is_glob: '['");

    // --- pm_is_regex: '/'...'/' delimited ---
    CHECK(pm_is_regex("libc.so") == false,        "is_regex: plain string");
    CHECK(pm_is_regex("/^encrypt/") == true,      "is_regex: delimited");
    CHECK(pm_is_regex("/") == false,              "is_regex: single slash is not delimited");
    CHECK(pm_is_regex("") == false,               "is_regex: empty string");

    // --- pm_match: exact mode (strcmp fallback) ---
    CHECK(pm_match("libc.so", "libc.so", true) == true,   "match exact: equal");
    CHECK(pm_match("libc.so", "libssl.so", true) == false, "match exact: not equal");
    CHECK(pm_match("*.so", "libc.so", true) == true,       "match exact: glob overrides exact flag");
    CHECK(pm_match("lib[co].so", "libc.so", true) == true, "match exact: '[' glob");
    CHECK(pm_match("lib[co].so", "libx.so", true) == false, "match exact: '[' glob no match");

    // --- pm_match: substring mode (strstr fallback) ---
    CHECK(pm_match("libc", "/system/lib64/libc.so", false) == true,
                                                   "match substr: found");
    CHECK(pm_match("libz", "/system/lib64/libc.so", false) == false,
                                                   "match substr: not found");
    CHECK(pm_match("*.so", "/system/lib64/libc.so", false) == true,
                                                   "match substr: glob overrides substr flag");

    // --- pm_regex: delimited and bare forms ---
    CHECK(pm_regex("/^lib/", "libc.so") == true,   "regex: delimited match");
    CHECK(pm_regex("/^lib/", "notlib.so") == false, "regex: delimited no match");
    CHECK(pm_regex("^lib", "libc.so") == true,     "regex: bare pattern match");
    CHECK(pm_regex("[", "anything") == false,      "regex: invalid pattern fails closed");

    // --- pm_regex_valid: parse-time syntax check, delimited and bare ---
    {
        char e[128];
        e[0] = '\0';
        CHECK(pm_regex_valid("/^lib/", e, sizeof e) == true, "regex_valid: delimited ok");
        e[0] = '\0';
        CHECK(pm_regex_valid("/[/", e, sizeof e) == false,   "regex_valid: delimited malformed");
        CHECK(e[0] != '\0',                                  "regex_valid: err message filled");
        e[0] = '\0';
        CHECK(pm_regex_valid("^lib", e, sizeof e) == true,   "regex_valid: bare ok");
        e[0] = '\0';
        CHECK(pm_regex_valid("[", e, sizeof e) == false,     "regex_valid: bare malformed");
        CHECK(e[0] != '\0',                                  "regex_valid: err message filled (bare)");
        // NULL err is fine (caller doesn't want the message).
        CHECK(pm_regex_valid("[", NULL, 0) == false,         "regex_valid: NULL err ok");
    }

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
