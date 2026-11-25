// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit test for common/engine_args.h's anubee_wants_help() —
// the MT1 fix's help/usage token detector.
//
// engine_args.h uses atoi()/pid_t without including <stdlib.h>/<unistd.h>
// itself (real engine .c files pull those in transitively before including
// it) — provide them here too rather than change the shared header for an
// unrelated reason.
#include <stdlib.h>
#include <unistd.h>

#include "common/engine_args.h"
#include "common/target_validate.h"

#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                         \
    checks++;                                         \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

// Delegate for a minimal argp table built in the -b bound tests below (see
// AUDIT.md #4 test case), same shape as each real engine's parse_opts.
static error_t engine_args_test_parser(int key, char *arg, struct argp_state *state)
{
    return parse_common_arg(key, arg, state, state->input);
}

// Every real engine calls argp_parse(..., ARGP_NO_EXIT, ...) (see MT1 above),
// and under that flag argp_error() prints its message and returns to the
// caller instead of exiting — it does NOT make argp_parse's own return value
// nonzero (verified empirically: the case 'b'/'Q' handlers still fall through
// to "return 0" after calling argp_error()). So the only observable signal
// that the new bound was hit is the message argp_error() writes to stderr;
// capture it here rather than trust argp_parse's return code.
static int bufsize_rejects(const char *val, const char *needle)
{
    static const struct argp_option opts[] = { COMMON_ARGP_OPTIONS, { 0 } };
    static const struct argp ap = { .options = opts, .parser = engine_args_test_parser };

    fflush(stderr);
    int saved_fd = dup(fileno(stderr));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stderr));

    struct common_args c = COMMON_ARGS_INIT;
    char *argv[] = { "test", "-b", (char *)val };
    argp_parse(&ap, 3, argv, ARGP_NO_EXIT, NULL, &c);

    fflush(stderr);
    dup2(saved_fd, fileno(stderr));
    close(saved_fd);

    char buf[512] = {0};
    rewind(tmp);
    fread(buf, 1, sizeof(buf) - 1, tmp);
    fclose(tmp);

    return strstr(buf, needle) != NULL;
}

// Parser that goes through the shared helpers, with the same end-of-args
// validation the engines do.
struct vargs { struct common_args c; struct target_args t; const char *pkg; int nsel; };

static error_t validate_test_parser(int key, char *arg, struct argp_state *state)
{
    struct vargs *v = state->input;
    switch (key) {
    case 'P': v->pkg = arg; return 0;
    case ARGP_KEY_END: {
        error_t e = validate_pid_or_package(state, v->t.n, v->pkg);
        if (e) return e;
        return validate_have_selector(state, v->nsel, "-e SPEC");
    }
    }
    error_t r = parse_target_arg(key, arg, state, &v->t);
    if (r != ARGP_ERR_UNKNOWN) return r;
    return parse_common_arg(key, arg, state, &v->c);
}

// argp_parse's own return value under ARGP_NO_EXIT: nonzero iff a parser
// reported an error.
static int parse_rc(int nsel, int argc, char **argv)
{
    static const struct argp_option opts[] = {
        COMMON_ARGP_OPTIONS, { "pid", 'p', "PID", 0, "", 0 }, { "pkg", 'P', "PKG", 0, "", 0 }, { 0 } };
    static const struct argp ap = { .options = opts, .parser = validate_test_parser };
    struct vargs v = { .c = COMMON_ARGS_INIT, .nsel = nsel };
    fflush(stderr);
    int saved = dup(fileno(stderr));
    FILE *sink = tmpfile();
    dup2(fileno(sink), fileno(stderr));
    int rc = argp_parse(&ap, argc, argv, ARGP_NO_EXIT, NULL, &v);
    fflush(stderr);
    dup2(saved, fileno(stderr));
    close(saved);
    fclose(sink);
    return rc;
}

int main(void)
{
    {
        char *argv[] = { "funcs", "-h" };
        CHECK(anubee_wants_help(2, argv) == true, "wants_help: -h");
    }
    {
        char *argv[] = { "funcs", "--help" };
        CHECK(anubee_wants_help(2, argv) == true, "wants_help: --help");
    }
    {
        char *argv[] = { "funcs", "-?" };
        CHECK(anubee_wants_help(2, argv) == true, "wants_help: -?");
    }
    {
        char *argv[] = { "funcs", "--usage" };
        CHECK(anubee_wants_help(2, argv) == true, "wants_help: --usage");
    }
    {
        char *argv[] = { "funcs", "-P", "x" };
        CHECK(anubee_wants_help(3, argv) == false, "wants_help: valid args, no help token");
    }
    {
        char *argv[] = { "funcs" };
        CHECK(anubee_wants_help(1, argv) == false, "wants_help: no args past argv[0]");
    }
    {
        // help token not in argv[0] (the subcommand name itself is never scanned)
        char *argv[] = { "--help" };
        CHECK(anubee_wants_help(1, argv) == false, "wants_help: argv[0] itself not scanned");
    }

    // AUDIT.md #4: -b/-Q now have an upper bound (previously unbounded, so a
    // typo like "-b 40000" silently proceeded to fail much later at BPF map
    // creation).
    {
        static const struct argp_option opts[] = { COMMON_ARGP_OPTIONS, { 0 } };
        static const struct argp ap = { .options = opts, .parser = engine_args_test_parser };

        struct common_args c = COMMON_ARGS_INIT;
        char *argv[] = { "test", "-b", "4096" };
        argp_parse(&ap, 3, argv, ARGP_NO_EXIT, NULL, &c);
        CHECK(c.bufmb == 4096, "bufsize: 4096 MB accepted (upper boundary)");
    }
    {
        CHECK(bufsize_rejects("40000", "must be between 1 and 4096"),
              "bufsize: 40000 MB rejected (over new upper bound)");
    }

    // argp_error must make argp_parse fail (previously it only printed and
    // the run carried on with bad arguments).
    {
        char *ok[]   = { "test", "-P", "x" };
        char *bad_b[] = { "test", "-P", "x", "-b", "0" };
        char *bad_q[] = { "test", "-P", "x", "-Q", "5000" };
        char *bad_p[] = { "test", "-p", "" };
        char *both[]  = { "test", "-P", "x", "-p", "1" };
        char *none[]  = { "test" };
        CHECK(parse_rc(1, 3, ok) == 0,     "valid -P with selector parses");
        CHECK(parse_rc(0, 3, ok) != 0,     "no selector fails");
        CHECK(parse_rc(1, 5, bad_b) != 0,  "-b 0 fails");
        CHECK(parse_rc(1, 5, bad_q) != 0,  "-Q 5000 fails");
        CHECK(parse_rc(1, 3, bad_p) != 0,  "-p with no PID fails");
        CHECK(parse_rc(1, 5, both) != 0,   "-p with -P fails");
        CHECK(parse_rc(1, 1, none) != 0,   "neither -p nor -P fails");
    }

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
