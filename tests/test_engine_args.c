// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit test for common/engine_args.h's ares_wants_help() —
// the MT1 fix's help/usage token detector.
//
// engine_args.h uses atoi()/pid_t without including <stdlib.h>/<unistd.h>
// itself (real engine .c files pull those in transitively before including
// it) — provide them here too rather than change the shared header for an
// unrelated reason.
#include <stdlib.h>
#include <unistd.h>

#include "common/engine_args.h"

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

int main(void)
{
    {
        char *argv[] = { "funcs", "-h" };
        CHECK(ares_wants_help(2, argv) == true, "wants_help: -h");
    }
    {
        char *argv[] = { "funcs", "--help" };
        CHECK(ares_wants_help(2, argv) == true, "wants_help: --help");
    }
    {
        char *argv[] = { "funcs", "-?" };
        CHECK(ares_wants_help(2, argv) == true, "wants_help: -?");
    }
    {
        char *argv[] = { "funcs", "--usage" };
        CHECK(ares_wants_help(2, argv) == true, "wants_help: --usage");
    }
    {
        char *argv[] = { "funcs", "-P", "x" };
        CHECK(ares_wants_help(3, argv) == false, "wants_help: valid args, no help token");
    }
    {
        char *argv[] = { "funcs" };
        CHECK(ares_wants_help(1, argv) == false, "wants_help: no args past argv[0]");
    }
    {
        // help token not in argv[0] (the subcommand name itself is never scanned)
        char *argv[] = { "--help" };
        CHECK(ares_wants_help(1, argv) == false, "wants_help: argv[0] itself not scanned");
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

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
