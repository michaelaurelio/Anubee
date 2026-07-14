// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the firewall-aware capability registry. Pins the one real
// invariant: only the uprobe-bearing objects write target memory.
#include "common/capabilities.h"

#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }   \
} while (0)

int main(void)
{
    int n = 0;
    const struct ares_bpf_object *objs = ares_bpf_objects(&n);
    CHECK(objs != NULL && n > 0, "registry non-empty");

    // Quiet capabilities write nothing into the target.
    CHECK(!ares_object_writes_target("syscalls"), "syscalls quiet");
    CHECK(!ares_object_writes_target("lib"),      "lib quiet");
    CHECK(!ares_object_writes_target("dump"),     "dump quiet");
    // Uprobe-bearing capabilities are loud.
    CHECK(ares_object_writes_target("funcs"),      "funcs loud");
    CHECK(ares_object_writes_target("correlate"),  "correlate loud");
    CHECK(ares_object_writes_target("trace"),      "trace loud");
    // AA2 fix: unknown name fails closed — treated as writing (loud), not
    // silently reported as stealthy for something unaudited.
    CHECK(ares_object_writes_target("nonexistent"), "unknown -> true (fail closed)");
    // Analyzers — stealthy ones are quiet, loud ones are not.
    CHECK(!ares_object_writes_target("mod:proc-event"), "mod:proc-event quiet");
    CHECK(!ares_object_writes_target("mod:execve"),    "mod:execve quiet");
    CHECK( ares_object_writes_target("mod:prop-read"), "mod:prop-read loud");
    CHECK(!ares_object_writes_target("mod:file-access"), "mod:file-access quiet");
    CHECK(!ares_object_writes_target("mod:massdelete-detect"), "mod:massdelete-detect quiet");
    CHECK(!ares_object_writes_target("mod:exfil-burst"), "mod:exfil-burst quiet");
    CHECK(!ares_object_writes_target("mod:a11y-abuse"), "mod:a11y-abuse quiet");
    CHECK(!ares_object_writes_target("mod:fileless-exec"), "mod:fileless-exec quiet");
    CHECK(!ares_object_writes_target("mod:mediaproj-abuse"), "mod:mediaproj-abuse quiet");

    int n2 = 0;
    (void)ares_bpf_objects(&n2);
    CHECK(n2 == 15, "registry has exactly 15 entries (6 engines + 9 analyzers) after mediaproj-abuse lands");

    // ares_quiet_config_ok: a quiet set passes; adding a loud object fails.
    const char *quiet_set[] = { "syscalls", "lib", "dump", "mod:proc-event" };
    CHECK(ares_quiet_config_ok(quiet_set, 4), "all-quiet config ok");
    const char *bad_set[] = { "syscalls", "funcs" };
    CHECK(!ares_quiet_config_ok(bad_set, 2), "quiet+loud config rejected");
    // A quiet set containing a loud analyzer is also rejected.
    const char *mod_bad_set[] = { "mod:proc-event", "mod:prop-read" };
    CHECK(!ares_quiet_config_ok(mod_bad_set, 2), "mod:proc-event+mod:prop-read rejected");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
