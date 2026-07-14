// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit tests for parse_custom_probe_spec — the custom probe-spec
// grammar (MOD!FUNC(S,V,F)>V, @offset, and malformed inputs). Pure logic, no
// device and no cross-toolchain: built and run on the host via `make test`.
#include "common/probe_resolve.h"
#include "common/probe_spec_loader.h"
#include "common/pattern_match.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int checks = 0, failures = 0;

// parse_custom_probe_spec takes a printf-style logger for error reporting;
// swallow it so malformed-input cases don't spam the test output.
static void noop_log(const char *fmt, ...) { (void)fmt; }

static custom_probe_spec_t S;
static int parse(const char *in) { return parse_custom_probe_spec(in, &S, noop_log); }

// parse_custom_probe_spec_ex: same grammar, plus a caller-supplied default
// kind for unprefixed input (used by syscalls' -e; see probe_resolve.h).
static bool used_default;
static int parse_ex(const char *in, spec_kind_t default_kind)
{
    return parse_custom_probe_spec_ex(in, &S, default_kind, &used_default, noop_log);
}

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

    // --- sockaddr arg type (C9) ---
    CHECK(parse("libc.so!connect(F,A,V)") == 0,  "connect: rc 0");
    CHECK(S.arg_count == 3 && S.arg_types[0] == ARG_FD &&
          S.arg_types[1] == ARG_SOCKADDR && S.arg_types[2] == ARG_VAL,
                                                 "connect: arg types F,A,V");

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

    // --- KIND: prefix (v2 grammar) ---
    // Explicit "funcs:" behaves identically to the unprefixed default.
    CHECK(parse("funcs:libc.so!open") == 0,      "kind funcs: rc 0");
    CHECK(S.kind == SPEC_KIND_FUNCS && S.deny == false &&
          strcmp(S.mod, "libc.so") == 0 && strcmp(S.func, "open") == 0,
                                                 "kind funcs: fields match bare form");

    // Unprefixed lines still default to SPEC_KIND_FUNCS (locks in the default).
    CHECK(parse("libc.so!open") == 0,            "kind default: rc 0");
    CHECK(S.kind == SPEC_KIND_FUNCS && S.deny == false, "kind default: FUNCS, not deny");

    // '/regex/'-delimited MODULE and FUNC sides: delimiters kept verbatim in
    // the struct (pattern_match interprets them); the '!' split is unaffected.
    CHECK(parse("libc.so!/^encrypt/") == 0,      "regex func: rc 0");
    CHECK(strcmp(S.mod, "libc.so") == 0 &&
          strcmp(S.func, "/^encrypt/") == 0,     "regex func: mod/func verbatim");
    CHECK(parse("/lib.*/!open") == 0,            "regex mod: rc 0");
    CHECK(strcmp(S.mod, "/lib.*/") == 0 &&
          strcmp(S.func, "open") == 0,           "regex mod: mod/func verbatim");

    // syscall: kind — bare NAME, no args/ret grammar.
    CHECK(parse("syscall:openat") == 0,          "kind syscall: rc 0");
    CHECK(S.kind == SPEC_KIND_SYSCALL && S.deny == false &&
          strcmp(S.mod, "openat") == 0,          "kind syscall: fields");
    // syscall: leading '!' = deny.
    CHECK(parse("syscall:!ptrace") == 0,         "kind syscall deny: rc 0");
    CHECK(S.kind == SPEC_KIND_SYSCALL && S.deny == true &&
          strcmp(S.mod, "ptrace") == 0,          "kind syscall deny: fields");

    // lib: kind — bare PATTERN (glob ok), no args/ret grammar.
    CHECK(parse("lib:libc.so") == 0,             "kind lib: rc 0");
    CHECK(S.kind == SPEC_KIND_LIB && S.deny == false &&
          strcmp(S.mod, "libc.so") == 0,         "kind lib: fields");
    CHECK(parse("lib:*.so") == 0,                "kind lib glob: rc 0");
    CHECK(S.kind == SPEC_KIND_LIB &&
          strcmp(S.mod, "*.so") == 0,            "kind lib glob: pattern verbatim");
    CHECK(parse("lib:!libbad.so") == 0,          "kind lib deny: rc 0");
    CHECK(S.kind == SPEC_KIND_LIB && S.deny == true &&
          strcmp(S.mod, "libbad.so") == 0,       "kind lib deny: fields");

    // mod: kind — bare NAME (analyzer registry), no deny/args/ret grammar.
    CHECK(parse("mod:execve") == 0,              "kind mod: rc 0");
    CHECK(S.kind == SPEC_KIND_MOD && S.deny == false &&
          strcmp(S.mod, "execve") == 0,          "kind mod: fields");

    // syscall:/lib:/mod: malformed rejections.
    CHECK(parse("syscall:openat(V)") == -1,      "err: syscall: rejects (args)");
    CHECK(parse("syscall:openat>V") == -1,       "err: syscall: rejects >ret");
    CHECK(parse("syscall:") == -1,               "err: syscall: empty pattern");
    CHECK(parse("lib:") == -1,                   "err: lib: empty pattern");
    CHECK(parse("mod:") == -1,                   "err: mod: empty name");

    // Unknown/mistyped KIND prefix: rejected outright rather than silently
    // mis-parsed as a MODULE!FUNC spec or (under a non-FUNCS default_kind)
    // as a literal pattern with the colon baked in.
    CHECK(parse("sycall:openat") == -1,          "err: unknown kind (typo)");
    CHECK(parse("foo:bar") == -1,                "err: unknown kind");
    CHECK(parse_ex("sycall:openat", SPEC_KIND_SYSCALL) == -1,
                                                  "err: unknown kind, even under syscall default");
    // Guard the heuristic against false positives: /regex/ modules and
    // MODULE!FUNC specs never contain an identifier-then-':' before '!'/'@'/
    // '/', so they must keep parsing as before.
    CHECK(parse("/lib.*/!open") == 0,            "regex mod still parses (no false unknown-kind)");
    CHECK(parse("libc.so!open") == 0,            "plain funcs spec still parses (no false unknown-kind)");

    // parse_custom_probe_spec_ex: engine-specific default kind for unprefixed
    // input (syscalls' -e defaulting to syscall:, see probe_resolve.h). -F
    // file loading never calls this with a non-FUNCS default — only single
    // -e values do — so these cases are the whole surface of the feature.
    CHECK(parse_ex("openat", SPEC_KIND_SYSCALL) == 0,
                                                  "ex bare default: rc 0");
    CHECK(S.kind == SPEC_KIND_SYSCALL && S.deny == false &&
          strcmp(S.mod, "openat") == 0,          "ex bare default: fields");
    CHECK(used_default == true,                  "ex bare default: used_default true");

    // Explicit prefix still wins; used_default must report false even though
    // the resulting kind happens to match default_kind.
    CHECK(parse_ex("syscall:openat", SPEC_KIND_SYSCALL) == 0,
                                                  "ex explicit prefix: rc 0");
    CHECK(S.kind == SPEC_KIND_SYSCALL &&
          strcmp(S.mod, "openat") == 0,          "ex explicit prefix: fields");
    CHECK(used_default == false,                 "ex explicit prefix: used_default false");

    // Deny form still works through the default path.
    CHECK(parse_ex("!ptrace", SPEC_KIND_SYSCALL) == 0,
                                                  "ex bare deny default: rc 0");
    CHECK(S.kind == SPEC_KIND_SYSCALL && S.deny == true &&
          strcmp(S.mod, "ptrace") == 0,          "ex bare deny default: fields");
    CHECK(used_default == true,                  "ex bare deny default: used_default true");

    // Safety property: a funcs-shaped bare value ('!' or '@') is NOT forced
    // into default_kind, even with one supplied — it still parses as funcs:
    // (and used_default stays false), so a funcs-style value accidentally
    // passed to e.g. syscalls' -e is silently ignored by that engine's own
    // kind filter instead of being mangled into a nonsensical syscall name.
    CHECK(parse_ex("libc.so!openat", SPEC_KIND_SYSCALL) == 0,
                                                  "ex funcs-shaped '!' wins: rc 0");
    CHECK(S.kind == SPEC_KIND_FUNCS &&
          strcmp(S.mod, "libc.so") == 0 &&
          strcmp(S.func, "openat") == 0,         "ex funcs-shaped '!' wins: fields");
    CHECK(used_default == false,                 "ex funcs-shaped '!' wins: used_default false");

    CHECK(parse_ex("libfoo.so@0x100", SPEC_KIND_SYSCALL) == 0,
                                                  "ex funcs-shaped '@' wins: rc 0");
    CHECK(S.kind == SPEC_KIND_FUNCS &&
          strcmp(S.mod, "libfoo.so") == 0,       "ex funcs-shaped '@' wins: fields");
    CHECK(used_default == false,                 "ex funcs-shaped '@' wins: used_default false");

    // default_kind == SPEC_KIND_FUNCS (funcs/correlate's own case, and the
    // plain parse_custom_probe_spec wrapper) never sets used_default, and
    // behaves byte-identically to plain parse() on the same input.
    CHECK(parse_ex("libc.so!open", SPEC_KIND_FUNCS) == 0,
                                                  "ex funcs default: rc 0");
    CHECK(used_default == false,                 "ex funcs default: used_default false");
    CHECK(parse("libc.so!open") == 0 &&
          S.kind == SPEC_KIND_FUNCS,             "plain wrapper: unaffected by _ex existing");

    // --- lockstep: every specs/*.spec line parses as its intended kind.
    // Originally (Phase 1) every line was plain FUNCS, proving the KIND-prefix
    // strip never fired on real spec files. EPIC H11 adds syscall:/lib: lines
    // to two of these files, so a line's own prefix now decides which
    // assertion applies -- still catches a real FUNCS line misclassified, or
    // a real syscall:/lib: line failing to be recognized as such. ---
    {
        static const char *const spec_files[] = {
            "specs/common-dynload.spec", "specs/common-file.spec",
            "specs/common-getprop.spec", "specs/common-network.spec",
            "specs/common-process.spec", "specs/common-string.spec",
            "specs/example-fd.spec",
        };
        int total_lines = 0;
        for (size_t fi = 0; fi < sizeof(spec_files) / sizeof(spec_files[0]); fi++) {
            FILE *f = fopen(spec_files[fi], "r");
            if (!f) {
                failures++; checks++;
                printf("  FAIL: lockstep: cannot open %s (run `make test` from repo root)\n",
                       spec_files[fi]);
                continue;
            }
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                char *end = line + strlen(line) - 1;
                while (end >= line && (*end == '\n' || *end == '\r' ||
                                        *end == ' ' || *end == '\t'))
                    *end-- = '\0';
                if (line[0] == '\0' || line[0] == '#') continue;
                checks++;
                total_lines++;
                bool expect_non_funcs = (strncmp(line, "syscall:", 8) == 0 ||
                                          strncmp(line, "lib:", 4) == 0);
                if (parse_custom_probe_spec(line, &S, noop_log) != 0) {
                    failures++;
                    printf("  FAIL: lockstep: %s: '%s' failed to parse\n",
                           spec_files[fi], line);
                } else if (!expect_non_funcs && (S.kind != SPEC_KIND_FUNCS || S.deny != false)) {
                    failures++;
                    printf("  FAIL: lockstep: %s: '%s' did not parse as plain FUNCS\n",
                           spec_files[fi], line);
                } else if (expect_non_funcs && S.kind == SPEC_KIND_FUNCS) {
                    failures++;
                    printf("  FAIL: lockstep: %s: '%s' expected non-FUNCS kind but got FUNCS\n",
                           spec_files[fi], line);
                }
            }
            fclose(f);
        }
        CHECK(total_lines > 0, "lockstep: at least one spec line was checked");
    }

    // --- load_probe_spec_file: reject-and-abort on a bad line, leading-ws
    // trim, line numbers. Writes small temp spec files rather than depending
    // on repo fixtures, so these run regardless of cwd. ---
    {
        char path[] = "/tmp/ares_test_probe_spec_loader.XXXXXX";
        int fd = mkstemp(path);
        CHECK(fd >= 0, "loader: mkstemp");
        if (fd >= 0) {
            custom_probe_spec_t specs[8];
            int count = 0;

            // Not found.
            CHECK(load_probe_spec_file("/nonexistent/path.spec", specs, 8, &count, noop_log) == -1,
                  "loader: file not found -> -1");

            // Blank lines, an indented comment, and an indented valid line
            // all load cleanly (leading-whitespace trim fixes the indented
            // '#'/spec cases; they must not be handed to the parser as-is).
            FILE *f = fdopen(fd, "w");
            fputs("\n  # indented comment\n  libc.so!open\nsyscall:openat\n", f);
            fclose(f); // also closes fd

            count = 0;
            CHECK(load_probe_spec_file(path, specs, 8, &count, noop_log) == 0,
                  "loader: blank/indented-comment/indented-spec file -> 0");
            CHECK(count == 2, "loader: two real lines counted");

            // A malformed line aborts the whole file: valid lines before it
            // are NOT rolled back (matches the documented "*count already
            // reflects prior successes" cursor semantics), but the call
            // reports failure and nothing after the bad line is read.
            f = fopen(path, "w");
            fputs("libc.so!open\nnoseparator\nsyscall:openat\n", f);
            fclose(f);

            count = 0;
            CHECK(load_probe_spec_file(path, specs, 8, &count, noop_log) == -1,
                  "loader: malformed line -> -1 (reject, not skip)");
            CHECK(count == 1, "loader: only the line before the bad one was counted");

            unlink(path);
        }
    }

    // --- custom_spec_matches_path: behavior preserved for non-'[' patterns,
    // one intentional delta documented (glob trigger "*?" -> "*?[") ---
    {
        custom_probe_spec_t spec;
        memset(&spec, 0, sizeof(spec));

        strcpy(spec.mod, "libc.so"); // exact basename, no glob/slash
        CHECK(custom_spec_matches_path(&spec, "/system/lib64/libc.so") == true,
              "matches_path: exact basename match");
        CHECK(custom_spec_matches_path(&spec, "/system/lib64/libssl.so") == false,
              "matches_path: exact basename no match");

        strcpy(spec.mod, "*.so"); // glob, unchanged trigger char
        CHECK(custom_spec_matches_path(&spec, "/system/lib64/libc.so") == true,
              "matches_path: glob basename match");
        CHECK(custom_spec_matches_path(&spec, "/system/lib64/libc.so.1") == false,
              "matches_path: glob basename no match");

        strcpy(spec.mod, "lib/mypath/libfoo.so"); // contains '/': full-path substring
        CHECK(custom_spec_matches_path(&spec, "/data/app/lib/mypath/libfoo.so") == true,
              "matches_path: slash pattern full-path substring");

        // Intentional delta (Phase 1): glob trigger widens "*?" -> "*?[". No
        // existing specs/*.spec line contains '[' (proven by the lockstep
        // check above), so this never fires on real spec files.
        strcpy(spec.mod, "lib[co].so");
        CHECK(custom_spec_matches_path(&spec, "/system/lib64/libc.so") == true,
              "matches_path: intentional '[' glob widening");

        // New capability (Phase 1): /regex/-delimited pattern, routed through
        // pm_regex rather than the slash-triggers-substring branch.
        strcpy(spec.mod, "/^libc/");
        CHECK(custom_spec_matches_path(&spec, "/system/lib64/libc.so") == true,
              "matches_path: /regex/ pattern (new capability)");
    }

    // --- seg_vaddr_to_off: vaddr-to-file-offset conversion ---
    // standard: p_vaddr == p_offset → no change
    {
        struct load_seg segs[] = {{ .vaddr = 0x0, .offset = 0x0, .filesz = 0x100000 }};
        CHECK(seg_vaddr_to_off(segs, 1, 0x1234) == 0x1234, "seg: identity (p_vaddr==p_offset)");
    }
    // packed .so: text at file 0x10000, mapped at vaddr 0x11000
    {
        struct load_seg segs[] = {{ .vaddr = 0x11000, .offset = 0x10000, .filesz = 0x8000 }};
        CHECK(seg_vaddr_to_off(segs, 1, 0x11abc) == 0x10abc, "seg: packed vaddr->off");
    }
    // vaddr outside all segments → sentinel (caller must skip, not wrong-offset attach)
    {
        struct load_seg segs[] = {{ .vaddr = 0x1000, .offset = 0x1000, .filesz = 0x100 }};
        CHECK(seg_vaddr_to_off(segs, 1, 0x9000) == SEG_VADDR_BAD, "seg: no match -> sentinel");
    }
    // empty segment table → sentinel
    CHECK(seg_vaddr_to_off(NULL, 0, 0x5678) == SEG_VADDR_BAD, "seg: empty table -> sentinel");

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
