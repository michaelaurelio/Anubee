// SPDX-License-Identifier: GPL-2.0
// Host unit tests for mod's analyzer-name de-duplication: a name given more
// than once (positionally and via -m, or via -m and a -F mod: line) must run
// that analyzer once -- each analyzer owns static skeleton state, so a second
// setup() would clobber the first and double every event.
#include <stdio.h>
#include <string.h>
#include "modules/mod_names.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static const char *dups[8];
static int ndups;
static void on_dup(const char *name) { dups[ndups++] = name; }
static int is_loud(const char *name) { return !strcmp(name, "prop-read"); }

int main(void)
{
    // positional + repeated -m, as in the old usage example
    const char *a[] = { "file-access", "file-access", "execve" };
    ndups = 0;
    int n = mod_dedupe_names(a, 3, on_dup);
    CHECK(n == 2, "duplicate dropped -> 2 names");
    CHECK(n == 2 && !strcmp(a[0], "file-access") && !strcmp(a[1], "execve"),
          "first-occurrence order kept");
    CHECK(ndups == 1 && !strcmp(dups[0], "file-access"), "duplicate reported once");

    // non-adjacent duplicates, several of them
    const char *b[] = { "execve", "proc-event", "execve", "file-access", "proc-event", "execve" };
    ndups = 0;
    n = mod_dedupe_names(b, 6, on_dup);
    CHECK(n == 3, "non-adjacent duplicates dropped -> 3 names");
    CHECK(n == 3 && !strcmp(b[0], "execve") && !strcmp(b[1], "proc-event")
                 && !strcmp(b[2], "file-access"), "order of survivors kept");
    CHECK(ndups == 3, "each extra occurrence reported");

    // no duplicates: untouched, no callback
    const char *c[] = { "execve", "proc-event" };
    ndups = 0;
    n = mod_dedupe_names(c, 2, on_dup);
    CHECK(n == 2 && ndups == 0, "no duplicates -> unchanged, no report");

    // NULL callback is allowed
    const char *d[] = { "execve", "execve" };
    CHECK(mod_dedupe_names(d, 2, NULL) == 1, "NULL on_dup still dedupes");

    // triage preset: every non-loud analyzer, registry order, at its position
    const char *reg[] = { "proc-event", "prop-read", "file-access", "perm-watch" };
    const char *e[16] = { "execve", "triage" };
    n = mod_expand_presets(e, 2, 16, reg, 4, is_loud);
    CHECK(n == 4, "triage -> 3 quiet analyzers after execve");
    CHECK(n == 4 && !strcmp(e[0], "execve") && !strcmp(e[1], "proc-event")
                 && !strcmp(e[2], "file-access") && !strcmp(e[3], "perm-watch"),
          "loud prop-read excluded, registry order kept");

    const char *f[16] = { "triage", "prop-read" };
    n = mod_expand_presets(f, 2, 16, reg, 4, is_loud);
    CHECK(n == 4 && !strcmp(f[3], "prop-read"), "explicit loud analyzer after the preset kept");

    const char *g[16] = { "triage", "file-access" };
    n = mod_expand_presets(g, 2, 16, reg, 4, is_loud);
    n = mod_dedupe_names(g, n, NULL);
    CHECK(n == 3, "explicit + preset duplicate removed by dedupe");

    const char *h[3] = { "triage" };
    CHECK(mod_expand_presets(h, 1, 2, reg, 4, is_loud) == -1, "cap too small -> -1");

    const char *k[4] = { "execve" };
    CHECK(mod_expand_presets(k, 1, 4, reg, 4, is_loud) == 1, "no preset -> unchanged");

    printf("test_mod_names: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
