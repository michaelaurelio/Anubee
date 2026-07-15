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

    // --- modcmp: the memory-vs-disk comparison record (dump --check) ---
    j.len = 0;
    dump_emit_modcmp(&j, "libsentinel.so", "/data/app/~~x==/lib/arm64/libsentinel.so",
                     0x7281a0000ULL, 25659, "differ",
                     "aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990",
                     "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff");
    HAS(j, "\"type\":\"modcmp\"",       "modcmp type");
    HAS(j, "\"module\":\"libsentinel.so\"", "modcmp module");
    HAS(j, "\"base\":\"0x7281a0000\"",  "modcmp base hex");
    HAS(j, "\"pid\":25659",             "modcmp pid");
    HAS(j, "\"state\":\"differ\"",      "modcmp state");
    HAS(j, "\"mem_sha256\":\"aaaabbbb", "modcmp mem digest");
    HAS(j, "\"file_sha256\":\"11112222", "modcmp file digest");

    // A clean library.
    j.len = 0;
    dump_emit_modcmp(&j, "libc.so", "/apex/com.android.runtime/lib64/bionic/libc.so",
                     0x7000000ULL, 25659, "match", "ab", "ab");
    HAS(j, "\"state\":\"match\"", "modcmp match state");

    // No disk backing: both digests are null, NOT empty strings - there is no
    // baseline to hash, and "" would read as a real (wrong) digest.
    j.len = 0;
    dump_emit_modcmp(&j, "[anon:dalvik]", "[anon:dalvik]", 0x48000000ULL, 25659,
                     "nofile", NULL, NULL);
    HAS(j, "\"state\":\"nofile\"",    "modcmp nofile state");
    HAS(j, "\"mem_sha256\":null",     "modcmp nofile mem null");
    HAS(j, "\"file_sha256\":null",    "modcmp nofile file null");

    // A short /proc/<pid>/mem read must NEVER be reported as differ: the memory
    // digest is meaningless, so it is null and the state says so.
    j.len = 0;
    dump_emit_modcmp(&j, "libfoo.so", "/tmp/libfoo.so", 0x10ULL, 7,
                     "unreadable", NULL, "cd");
    HAS(j, "\"state\":\"unreadable\"", "modcmp unreadable state");
    HAS(j, "\"mem_sha256\":null",      "modcmp unreadable mem null");

    // JSON-significant chars in the module name escape.
    j.len = 0;
    dump_emit_modcmp(&j, "lib\"q\".so", "/tmp/lib\"q\".so", 0x20ULL, 8, "match", "a", "a");
    HAS(j, "\\\"q\\\"", "modcmp escaped quotes");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
