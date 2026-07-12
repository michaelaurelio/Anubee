// SPDX-License-Identifier: GPL-2.0
// Host unit tests for jsonl_merge (EPIC C5: combine each engine's own -o file
// into one at the literal -o path).
#include "common/jsonl_merge.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } } while (0)

// Read the entire contents of a file into a malloc'd buffer (NUL-terminated).
// Mirrors test_emit.c's own slurp() helper.
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    fputs(content, f);
    fclose(f);
}

int main(void)
{
    // Concatenation in order, no separators added (each source is already a
    // complete JSONL file, one record per line with its own trailing newline).
    {
        write_file("/tmp/test_merge_a.jsonl", "{\"a\":1}\n{\"a\":2}\n");
        write_file("/tmp/test_merge_b.jsonl", "{\"b\":1}\n");
        const char *srcs[] = { "/tmp/test_merge_a.jsonl", "/tmp/test_merge_b.jsonl" };
        int n = jsonl_merge("/tmp/test_merge_out.jsonl", srcs, 2);
        CHECK(n == 2, "merge: both sources counted");
        char *got = slurp("/tmp/test_merge_out.jsonl");
        CHECK(got && strcmp(got, "{\"a\":1}\n{\"a\":2}\n{\"b\":1}\n") == 0, "merge: concatenated in order");
        free(got);
    }

    // A missing source among the list is skipped, not a failure - the
    // remaining sources still merge and the count reflects only what existed.
    {
        write_file("/tmp/test_merge_c.jsonl", "{\"c\":1}\n");
        const char *srcs[] = { "/tmp/test_merge_c.jsonl", "/tmp/test_merge_does_not_exist.jsonl" };
        int n = jsonl_merge("/tmp/test_merge_out2.jsonl", srcs, 2);
        CHECK(n == 1, "merge: missing source skipped, count reflects only real files");
        char *got = slurp("/tmp/test_merge_out2.jsonl");
        CHECK(got && strcmp(got, "{\"c\":1}\n") == 0, "merge: existing source still merged");
        free(got);
    }

    // Zero sources: dst is still created (empty), count is 0 - not an error.
    {
        int n = jsonl_merge("/tmp/test_merge_out3.jsonl", NULL, 0);
        CHECK(n == 0, "merge: zero sources -> count 0");
        char *got = slurp("/tmp/test_merge_out3.jsonl");
        CHECK(got && strcmp(got, "") == 0, "merge: empty dst file still created");
        free(got);
    }

    // Unwritable dst path -> -1, no crash.
    {
        int n = jsonl_merge("/tmp/does/not/exist/out.jsonl", NULL, 0);
        CHECK(n == -1, "merge: unwritable dst returns -1");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
