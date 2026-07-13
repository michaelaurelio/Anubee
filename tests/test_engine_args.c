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

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                         \
    checks++;                                         \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

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

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
