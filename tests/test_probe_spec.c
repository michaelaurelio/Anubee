// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit tests for parse_custom_probe_spec — the custom probe-spec
// grammar (MOD!FUNC(S,V,F)>V, @offset, and malformed inputs). Pure logic, no
// device and no cross-toolchain: built and run on the host via `make test`.
#include "common/probe_resolve.h"

#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;

// parse_custom_probe_spec takes a printf-style logger for error reporting;
// swallow it so malformed-input cases don't spam the test output.
static void noop_log(const char *fmt, ...) { (void)fmt; }

static custom_probe_spec_t S;
static int parse(const char *in) { return parse_custom_probe_spec(in, &S, noop_log); }

#define CHECK(cond, msg) do {                         \
    checks++;                                         \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // --- bare MOD!FUNC: heuristic args, no return probe ---
    CHECK(parse("libc.so!open") == 0,            "open: rc 0");
    CHECK(strcmp(S.mod, "libc.so") == 0,         "open: mod");
    CHECK(strcmp(S.func, "open") == 0,           "open: func");
    CHECK(S.arg_count == -1,                     "open: arg_count default -1");
    CHECK(S.ret_type == ARG_NONE,                "open: ret none");
    CHECK(S.ret_only == false,                   "open: not ret_only");
    CHECK(S.offset == 0,                         "open: offset 0");

    // --- typed args + return type ---
    CHECK(parse("libc.so!fgets(S,V,V)>V") == 0,  "fgets: rc 0");
    CHECK(S.arg_count == 3,                       "fgets: arg_count 3");
    CHECK(S.arg_types[0] == ARG_STR &&
          S.arg_types[1] == ARG_VAL &&
          S.arg_types[2] == ARG_VAL,             "fgets: arg types S,V,V");
    CHECK(S.ret_type == ARG_VAL,                 "fgets: ret val");
    CHECK(S.ret_only == false,                   "fgets: paired, not ret_only");

    // --- fd arg type ---
    CHECK(parse("libc.so!read(F)") == 0,         "read: rc 0");
    CHECK(S.arg_count == 1 && S.arg_types[0] == ARG_FD, "read: one fd arg");
    CHECK(S.ret_type == ARG_NONE,                "read: no return probe");

    // --- @offset, no function name ---
    CHECK(parse("libc.so@0x1234") == 0,          "offset: rc 0");
    CHECK(strcmp(S.mod, "libc.so") == 0 && S.func[0] == '\0', "offset: mod, empty func");
    CHECK(S.offset == 0x1234,                    "offset: 0x1234");

    // --- function name AND explicit offset ---
    CHECK(parse("libc.so!open@0x10") == 0,       "func@off: rc 0");
    CHECK(strcmp(S.func, "open") == 0 && S.offset == 0x10, "func@off: func + offset");

    // --- '>ret' with no parens = return-only probe ---
    CHECK(parse("libc.so!open>V") == 0,          "ret_only: rc 0");
    CHECK(S.ret_type == ARG_VAL && S.arg_count == -1 && S.ret_only == true,
                                                 "ret_only: flags");

    // --- '()>ret' = paired (CALL + RET), NOT ret_only ---
    CHECK(parse("libc.so!open()>V") == 0,        "paired: rc 0");
    CHECK(S.arg_count == 0 && S.ret_type == ARG_VAL && S.ret_only == false,
                                                 "paired: arg_count 0, not ret_only");

    // --- lowercase type letters accepted ---
    CHECK(parse("libc.so!read(s,v,f)>v") == 0,   "lowercase: rc 0");
    CHECK(S.arg_types[0] == ARG_STR && S.arg_types[1] == ARG_VAL &&
          S.arg_types[2] == ARG_FD && S.ret_type == ARG_VAL, "lowercase: types");

    // --- arg list clamps at 8 (9th dropped, still valid) ---
    CHECK(parse("libc.so!f(V,V,V,V,V,V,V,V,V)") == 0, "argcap: rc 0");
    CHECK(S.arg_count == 8,                       "argcap: clamped to 8");

    // --- malformed inputs must be rejected (rc -1) ---
    CHECK(parse("noseparator") == -1,            "err: no '!' or '@'");
    CHECK(parse("libc.so!open(X)") == -1,        "err: unknown arg type");
    CHECK(parse("libc.so!open(S") == -1,         "err: unclosed paren");
    CHECK(parse("libc.so!open>Z") == -1,         "err: unknown return type");
    CHECK(parse("!open") == -1,                  "err: empty module");
    CHECK(parse("libc.so!") == -1,               "err: no func name or offset");

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
