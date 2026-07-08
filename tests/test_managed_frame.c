// SPDX-License-Identifier: GPL-2.0
// Host unit test for the pure managed-chain builder + stack_id cache.
#include "common/managed_frame.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

int main(void)
{
    char out[256];

    // AOT managed frames: module prefix stripped, innermost-first, natives elided.
    const char *a[] = {
        "libc.so!__openat",                          // native  -> elided
        "libandroid_runtime.so!JNI_stuff",           // native  -> elided
        "boot.oat!pkg.Inner.method",                 // managed -> kept
        "base.odex!pkg.Outer.method",                // managed -> kept
    };
    const char *nt1[] = { "pkg.Nterp.run" };
    int n = ares_managed_chain_build(a, 4, NULL, 0, out, sizeof(out));
    CHECK(n == 2, "counts only managed frames");
    CHECK(strcmp(out, "[\"pkg.Inner.method\",\"pkg.Outer.method\"]") == 0,
          "strips module prefix, order preserved, natives elided");

    // Pure-native stack: nothing to emit.
    const char *b[] = { "libc.so!read", "linker64!__dl__Z" };
    out[0] = 'X';
    n = ares_managed_chain_build(b, 2, NULL, 0, out, sizeof(out));
    CHECK(n == 0, "no managed frame -> 0");
    CHECK(out[0] == 'X', "out untouched when empty");

    // nterp terminal: no managed frames, single interpreted method appended.
    const char *c[] = { "libc.so!__openat", "libart.so!nterp_helper" };
    n = ares_managed_chain_build(c, 2, nt1, 1, out, sizeof(out));
    CHECK(n == 1, "nterp name appended as one method");
    CHECK(strcmp(out, "[\"pkg.Nterp.run\"]") == 0, "nterp-only chain");

    // Multi-frame interpreted chain: all appended, innermost-first.
    const char *nt3[] = { "pkg.A.a+0x2", "pkg.B.b+0x4", "pkg.C.c" };
    n = ares_managed_chain_build(c, 2, nt3, 3, out, sizeof(out));
    CHECK(n == 3, "full nterp chain counted");
    CHECK(strcmp(out, "[\"pkg.A.a+0x2\",\"pkg.B.b+0x4\",\"pkg.C.c\"]") == 0,
          "nterp chain innermost-first");

    // Empty strings in the nterp array are skipped, not counted.
    const char *nt_gap[] = { "pkg.A.a", "", "pkg.C.c" };
    n = ares_managed_chain_build(c, 2, nt_gap, 3, out, sizeof(out));
    CHECK(n == 2 && strcmp(out, "[\"pkg.A.a\",\"pkg.C.c\"]") == 0, "empty nterp name skipped");

    // Managed frames + nterp chain appended last.
    n = ares_managed_chain_build(a, 4, nt3, 3, out, sizeof(out));
    CHECK(n == 5, "managed + full nterp chain counted");
    CHECK(strcmp(out, "[\"pkg.Inner.method\",\"pkg.Outer.method\",\"pkg.A.a+0x2\",\"pkg.B.b+0x4\",\"pkg.C.c\"]") == 0,
          "nterp chain appended after managed");

    // JSON escaping of a pathological method name.
    const char *d[] = { "boot.oat!pkg.Q\"x" };
    n = ares_managed_chain_build(d, 1, NULL, 0, out, sizeof(out));
    CHECK(n == 1 && strcmp(out, "[\"pkg.Q\\\"x\"]") == 0, "escapes quote in name");

    // art_jni_trampoline lives in boot.oat (resolves "boot.oat!art_jni_trampoline+..")
    // but is a native bridge, not a Java method — must be excluded from the chain.
    const char *t[] = {
        "libc.so!__openat",
        "boot.oat!art_jni_trampoline+0x6c",          // bridge -> excluded
        "boot.oat!pkg.Inner.method",                 // managed -> kept
    };
    n = ares_managed_chain_build(t, 3, NULL, 0, out, sizeof(out));
    CHECK(n == 1, "art_jni_trampoline excluded from managed chain");
    CHECK(strcmp(out, "[\"pkg.Inner.method\"]") == 0, "trampoline not in java_stack");

    // Overflow: a chain longer than cap is TRUNCATED with a "..." marker, never
    // dropped whole. Real Kotlin/Compose names make chains routinely exceed the
    // cache fragment size; all-or-nothing drop silently loses the whole java_stack.
    const char *big[] = {
        "boot.oat!pkg.Alpha.one", "boot.oat!pkg.Beta.two", "boot.oat!pkg.Gamma.three",
    };
    char small[36];
    n = ares_managed_chain_build(big, 3, NULL, 0, small, sizeof(small));
    CHECK(n > 0, "overflow truncates instead of dropping (n>0)");
    CHECK(strlen(small) + 1 <= sizeof(small), "truncated fragment fits within cap");
    CHECK(strlen(small) > 0 && small[strlen(small) - 1] == ']', "truncated output is a closed JSON array");
    CHECK(strstr(small, "\"...\"") != NULL, "truncation marker present");
    CHECK(strstr(small, "pkg.Alpha.one") != NULL, "keeps the innermost frame(s)");

    // A chain that fits exactly is emitted whole, with no marker.
    char just[64];
    n = ares_managed_chain_build(big, 3, NULL, 0, just, sizeof(just));
    CHECK(n == 3 && strstr(just, "\"...\"") == NULL, "no marker when the whole chain fits");

    // is_interp_frame classification.
    CHECK(ares_is_interp_frame("libart.so!nterp_helper"), "nterp_helper is interp");
    CHECK(ares_is_interp_frame("libart.so!art_quick_to_interpreter_bridge_ToInterpreterBridge"),
          "ToInterpreterBridge is interp");
    CHECK(!ares_is_interp_frame("libc.so!__openat"), "native is not interp");
    CHECK(!ares_is_interp_frame(NULL), "NULL is not interp");

    // Cache: put/get round-trip, miss, overwrite, reset.
    char buf[208];
    ares_jcache_reset();
    CHECK(ares_jcache_get(42, buf, sizeof(buf)) == 0, "cache miss before put");
    ares_jcache_put(42, "[\"pkg.A.b\"]");
    CHECK(ares_jcache_get(42, buf, sizeof(buf)) == 1 && strcmp(buf, "[\"pkg.A.b\"]") == 0, "cache hit round-trip");
    CHECK(ares_jcache_get(43, buf, sizeof(buf)) == 0, "different id misses");
    ares_jcache_put(42, "[\"pkg.C.d\"]");
    CHECK(ares_jcache_get(42, buf, sizeof(buf)) == 1 && strcmp(buf, "[\"pkg.C.d\"]") == 0, "put overwrites same id");
    ares_jcache_reset();
    CHECK(ares_jcache_get(42, buf, sizeof(buf)) == 0, "reset clears");

    printf(fails ? "\n%d FAILED\n" : "\nALL PASSED\n", fails);
    return fails ? 1 : 0;
}
