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
    int n = ares_managed_chain_build(a, 4, NULL, out, sizeof(out));
    CHECK(n == 2, "counts only managed frames");
    CHECK(strcmp(out, "[\"pkg.Inner.method\",\"pkg.Outer.method\"]") == 0,
          "strips module prefix, order preserved, natives elided");

    // Pure-native stack: nothing to emit.
    const char *b[] = { "libc.so!read", "linker64!__dl__Z" };
    out[0] = 'X';
    n = ares_managed_chain_build(b, 2, NULL, out, sizeof(out));
    CHECK(n == 0, "no managed frame -> 0");
    CHECK(out[0] == 'X', "out untouched when empty");

    // nterp terminal: no managed frames, single interpreted method appended.
    const char *c[] = { "libc.so!__openat", "libart.so!nterp_helper" };
    n = ares_managed_chain_build(c, 2, "pkg.Nterp.run", out, sizeof(out));
    CHECK(n == 1, "nterp name appended as one method");
    CHECK(strcmp(out, "[\"pkg.Nterp.run\"]") == 0, "nterp-only chain");

    // Managed frames + nterp terminal appended last.
    n = ares_managed_chain_build(a, 4, "pkg.Nterp.run", out, sizeof(out));
    CHECK(n == 3, "managed + nterp counted");
    CHECK(strcmp(out, "[\"pkg.Inner.method\",\"pkg.Outer.method\",\"pkg.Nterp.run\"]") == 0,
          "nterp appended after managed");

    // JSON escaping of a pathological method name.
    const char *d[] = { "boot.oat!pkg.Q\"x" };
    n = ares_managed_chain_build(d, 1, NULL, out, sizeof(out));
    CHECK(n == 1 && strcmp(out, "[\"pkg.Q\\\"x\"]") == 0, "escapes quote in name");

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
