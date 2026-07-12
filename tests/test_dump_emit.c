// SPDX-License-Identifier: GPL-2.0
// Host unit test for dump's structured record builder (SYM1 Phase 3: dump's
// previously-nonexistent machine channel). Pins the JSON shape.
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "dump/dump_emit.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0, failures = 0;
#define HAS(j, sub, msg) do {                                        \
    checks++;                                                        \
    char tmp[4096]; int n = (int)(j).len; if (n > 4095) n = 4095;    \
    memcpy(tmp, (j).b, n); tmp[n] = 0;                               \
    if (!strstr(tmp, sub)) { failures++;                            \
        printf("  FAIL: %s\n    in: %s\n", msg, tmp); }              \
} while (0)

int main(void)
{
    struct jbuf j = {0};

    dump_emit_module(&j, "libfoo.so", "/tmp/out/libfoo.so.1234.7a000000.so",
                     0x7a000000ULL, 1234, 0);
    HAS(j, "\"type\":\"dump\"",   "dump type");
    HAS(j, "\"module\":\"libfoo.so\"", "dump module name");
    HAS(j, "\"path\":\"/tmp/out/libfoo.so.1234.7a000000.so\"", "dump path");
    HAS(j, "\"base\":\"0x7a000000\"", "dump base hex");
    HAS(j, "\"pid\":1234",        "dump pid");
    HAS(j, "\"raw\":false",       "dump raw=false");

    j.len = 0;
    dump_emit_module(&j, "libbar.so", "/tmp/out/libbar.so.5.b0.so", 0xb0ULL, 5, 1);
    HAS(j, "\"raw\":true", "dump raw=true");

    // JSON-significant chars in path escape correctly.
    j.len = 0;
    dump_emit_module(&j, "lib\"evil\".so", "/tmp/out/lib\"evil\".so", 0x10ULL, 1, 0);
    HAS(j, "\\\"evil\\\"", "dump escaped quotes in path");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
