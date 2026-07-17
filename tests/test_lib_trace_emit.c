// SPDX-License-Identifier: GPL-2.0
// Host unit tests for anubee_libtrace_emit_lib/unlib via anubee_sink.
// Pins the JSON field names and escaping so the schema is stable for anubee-mcp ingest.
#include <linux/types.h>
#include <stdbool.h>
#include "common/emit.h"
#include "common/lib_trace.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int checks = 0, failures = 0;
#define CHECK_HAS(buf, sub, msg) do {                                \
    checks++;                                                        \
    if (!strstr(buf, sub)) { failures++;                            \
        printf("  FAIL: %s\n    want: %s\n    in: %s\n", msg, sub, buf); } \
} while (0)

// Read entire file into a malloc'd buffer (caller frees). Returns NULL on error.
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

int main(void)
{
    char tmppath[] = "/tmp/test_lib_trace_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0) { perror("mkstemp"); return 1; }
    close(fd);

    struct anubee_sink sink = {0};
    if (anubee_sink_open(&sink, tmppath, "lib", 1) != 0) {
        fprintf(stderr, "anubee_sink_open failed\n");
        remove(tmppath);
        return 1;
    }

    struct lib_map_event e = {0};
    e.h.pid = 1234; e.h.tid = 1240; e.ppid = 100;
    e.start = 0xb4000000; e.end = 0xb4001000; e.pgoff = 0; e.inode = 42;

    // plain path
    anubee_libtrace_emit_lib(&sink, /*quiet=*/1, &e, "/data/app/libc.so", NULL);
    // path with JSON-significant chars
    anubee_libtrace_emit_lib(&sink, /*quiet=*/1, &e, "/data/app/lib\"evil\".so", NULL);
    // with soname
    anubee_libtrace_emit_lib(&sink, /*quiet=*/1, &e, "/data/app/libexample.so", "libexample.so");

    struct lib_unmap_event u = {0};
    u.h.pid = 5678; u.h.tid = 5680;
    u.start = 0xc0000000; u.end = 0xc0002000;
    anubee_libtrace_emit_unlib(&sink, /*quiet=*/1, &u);

    // MT3: packed-in-APK enumeration record
    struct apk_so_ref ref = {0};
    snprintf(ref.name, sizeof(ref.name), "libsentinel.so");
    ref.data_start = 12345;
    ref.size       = 6789;
    anubee_libtrace_emit_packed(&sink, /*quiet=*/1, "/data/app/base.apk", &ref);

    anubee_sink_close(&sink);
    free(sink.jb.b);

    char *out = slurp(tmppath);
    remove(tmppath);
    if (!out) { fprintf(stderr, "slurp failed\n"); return 1; }

    CHECK_HAS(out, "\"type\":\"lib\"",                    "lib type field");
    CHECK_HAS(out, "\"pid\":1234",                        "lib pid");
    CHECK_HAS(out, "\"library\":\"/data/app/libc.so\"",  "lib library path");
    CHECK_HAS(out, "\"start\":\"0xb4000000\"",            "lib start hex");
    CHECK_HAS(out, "\"inode\":42",                        "lib inode");
    CHECK_HAS(out, "\\\"evil\\\"",                        "lib escaped quotes in path");
    CHECK_HAS(out, "\"soname\":\"libexample.so\"",           "lib soname field");
    CHECK_HAS(out, "\"type\":\"unlib\"",                  "unlib type field");
    CHECK_HAS(out, "\"pid\":5678",                        "unlib pid");
    CHECK_HAS(out, "\"start\":\"0xc0000000\"",            "unlib start hex");
    CHECK_HAS(out, "\"end\":\"0xc0002000\"",              "unlib end hex");
    CHECK_HAS(out, "\"type\":\"lib_packed\"",             "lib_packed type field");
    CHECK_HAS(out, "\"apk\":\"/data/app/base.apk\"",      "lib_packed apk path");
    CHECK_HAS(out, "\"soname\":\"libsentinel.so\"",       "lib_packed soname");
    CHECK_HAS(out, "\"offset\":12345",                    "lib_packed offset");
    CHECK_HAS(out, "\"size\":6789",                       "lib_packed size");

    free(out);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
