// SPDX-License-Identifier: GPL-2.0
// Host unit tests for binder-api's Parcel token decode and DEX method naming.
// argv[1] = tests/fixtures/binder_stub.dex, argv[2] = tests/fixtures/binder_stub.jar,
// argv[3] = tests/fixtures/binder_stub_dd.jar
// (built from tests/fixtures/binder_stub/IFoo.java by gen_binder_stub.sh).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "modules/binder_api_parse.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static size_t mk_parcel(unsigned char *b, const char *tok, int len_override)
{
    memset(b, 0, 256);
    b[0] = 0x00; b[1] = 0x00; b[2] = 0x00; b[3] = 0x40;   // policy
    b[4] = 0xff; b[5] = 0xff; b[6] = 0xff; b[7] = 0xff;   // work source -1
    memcpy(b + 8, "TSYS", 4);                              // 'SYST' as LE int32
    int len = len_override >= 0 ? len_override : (int)strlen(tok);
    memcpy(b + 12, &len, 4);
    size_t i = 0;
    for (; tok[i]; i++) { b[16 + 2 * i] = (unsigned char)tok[i]; b[17 + 2 * i] = 0; }
    return 16 + 2 * i + 2 + 8;   // NUL + some payload
}

static unsigned char *slurp(const char *p, size_t *len)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)n);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

int main(int argc, char **argv)
{
    unsigned char p[256];
    char tok[160];
    size_t n = mk_parcel(p, "android.view.accessibility.IAccessibilityManager", -1);
    CHECK(binder_parcel_token(p, n, tok, sizeof tok) == 48 &&
          !strcmp(tok, "android.view.accessibility.IAccessibilityManager"), "token decoded");

    n = mk_parcel(p, "android.os.IServiceManager", -1);
    CHECK(binder_parcel_token(p, 20, tok, sizeof tok) == -1, "truncated raw -> -1");
    CHECK(binder_parcel_token(p, n, tok, 8) == -1, "token longer than out -> -1");
    n = mk_parcel(p, "x", 0);
    CHECK(binder_parcel_token(p, n, tok, sizeof tok) == -1, "zero length -> -1");
    n = mk_parcel(p, "x", -5 + 0x7fffffff);
    CHECK(binder_parcel_token(p, n, tok, sizeof tok) == -1, "huge length -> -1");
    n = mk_parcel(p, "ab", -1);
    p[16] = 0x07;   // control char: not a token
    CHECK(binder_parcel_token(p, n, tok, sizeof tok) == -1, "non-printable -> -1");

    // hash: matches the kernel's FNV-1a over UTF-16LE bytes of the token
    n = mk_parcel(p, "ab", -1);
    unsigned long long want = 1469598103934665603ULL;
    const unsigned char bytes[4] = { 'a', 0, 'b', 0 };
    for (int i = 0; i < 4; i++) { want ^= bytes[i]; want *= 1099511628211ULL; }
    CHECK(binder_token_hash(p, n) == want, "hash = FNV-1a(UTF-16LE token)");
    CHECK(binder_token_hash(p, 10) == 0, "no token -> hash 0");
    CHECK(binder_descriptor_hash("a.B") == 0x7d05b88aa76770eeULL,
          "descriptor hash = FNV-1a over its UTF-16LE bytes (what the kernel hashes)");
    CHECK(binder_descriptor_hash("") == 0, "empty descriptor -> 0 (never matches)");

    // ---- IContentProvider detail: layouts as captured on an Android 16 device ----
    {
        unsigned char b[512];
        size_t o;
        struct binder_cp_detail d;
#define PUT32(v) do { int32_t _v = (v); memcpy(b + o, &_v, 4); o += 4; } while (0)
#define PUTS16(s) do { const char *_s = (s); int32_t _l = (int32_t)strlen(_s); PUT32(_l); \
        for (int _i = 0; _i <= _l; _i++) { b[o++] = (unsigned char)_s[_i]; b[o++] = 0; } \
        while (o % 4) b[o++] = 0; } while (0)
#define PUTS8(s) do { const char *_s = (s); int32_t _l = (int32_t)strlen(_s); PUT32(_l); \
        memcpy(b + o, _s, (size_t)_l + 1); o += (size_t)_l + 1; while (o % 4) b[o++] = 0; } while (0)
        // header + token + AttributionSource-shaped prefix (own package as String16)
#define PROLOGUE() do { memset(b, 0, sizeof b); o = 0; PUT32((int32_t)0x80000000); PUT32(-1); \
        memcpy(b + o, "TSYS", 4); o += 4; PUTS16("android.content.IContentProvider"); \
        PUT32(0x6c); PUT32(10161); PUT32(9999); PUT32(0); PUTS16("com.example.app"); \
        PUT32(-1); PUT32(0x73622a85); PUT32(0x113); } while (0)

        PROLOGUE(); PUT32(1); PUTS8("content://sms/inbox"); PUT32(1); PUTS16("_id");
        CHECK(binder_cp_describe(b, o, 0, &d) == 1 && !strcmp(d.uri, "content://sms/inbox"),
              "QUERY: StringUri (UTF-8) extracted");
        CHECK(!d.authority[0], "QUERY: no CALL fields");

        PROLOGUE(); PUT32(1); PUTS8("content://media/internal/audio/media/44?title=Rise%20Slowly&canonical=1");
        CHECK(binder_cp_describe(b, o, 0, &d) == 1 &&
              !strcmp(d.uri, "content://media/internal/audio/media/44?title=Rise%20Slowly&canonical=1"),
              "URI with query string kept whole");

        PROLOGUE(); PUT32(1); PUTS16("content://com.android.contacts/contacts");
        CHECK(binder_cp_describe(b, o, 0, &d) == 1 && !strcmp(d.uri, "content://com.android.contacts/contacts"),
              "UTF-16 content:// fallback");

        PROLOGUE(); PUTS16("settings"); PUTS16("GET_secure"); PUTS16("android_id");
        PUT32(0x30); memcpy(b + o, "BNDL", 4); o += 4; PUT32(1);
        CHECK(binder_cp_describe(b, o, 1, &d) == 1 && !strcmp(d.authority, "settings") &&
              !strcmp(d.method, "GET_secure") && !strcmp(d.arg, "android_id"),
              "CALL: authority/method/arg before the Bundle");
        CHECK(!d.uri[0], "CALL: no uri");

        PROLOGUE(); PUTS16("com.example.provider"); PUTS16("doThing"); PUT32(-1); PUT32(-1);
        CHECK(binder_cp_describe(b, o, 1, &d) == 1 && !strcmp(d.authority, "com.example.provider") &&
              !strcmp(d.method, "doThing") && !d.arg[0], "CALL: null arg, null extras");

        PROLOGUE(); PUT32(1);
        CHECK(binder_cp_describe(b, o, 0, &d) == 0, "no URI present -> 0");
        CHECK(binder_cp_describe(b, 10, 1, &d) == 0, "truncated -> 0");
    }

    if (argc < 4) { printf("usage: %s binder_stub.dex binder_stub.jar binder_stub_dd.jar\n", argv[0]); return 2; }
    size_t dlen = 0, jlen = 0, ddlen = 0;
    unsigned char *dex = slurp(argv[1], &dlen), *jar = slurp(argv[2], &jlen),
                  *ddjar = slurp(argv[3], &ddlen);
    CHECK(dex && jar && ddjar, "fixtures readable");
    if (!dex || !jar || !ddjar) goto out;

    struct binder_names *bn = binder_names_new();
    CHECK(binder_names_add_dex(bn, dex, dlen) == 5, "3 AIDL TRANSACTION_ + 2 hand-written _TRANSACTION");
    CHECK(binder_names_lookup(bn, "com.anubee.legacy.IHand", 1) &&
          !strcmp(binder_names_lookup(bn, "com.anubee.legacy.IHand", 1), "QUERY"),
          "hand-written interface keyed by its descriptor constant: QUERY_TRANSACTION -> QUERY");
    CHECK(!binder_names_lookup(bn, "com.anubee.aidl.IHand", 1),
          "class name is not the key when a descriptor constant exists");
    CHECK(binder_names_lookup(bn, "com.anubee.legacy.IHand", 2) &&
          !strcmp(binder_names_lookup(bn, "com.anubee.legacy.IHand", 2), "GET_TYPE"),
          "hand-written interface: multi-word name");
    CHECK(!binder_names_lookup(bn, "com.anubee.legacy.IHand", 3), "non-_TRANSACTION constant ignored");
    CHECK(binder_names_lookup(bn, "com.anubee.aidl.IFoo", 1) &&
          !strcmp(binder_names_lookup(bn, "com.anubee.aidl.IFoo", 1), "ping"), "code 1 -> ping");
    CHECK(binder_names_lookup(bn, "com.anubee.aidl.IFoo", 2) &&
          !strcmp(binder_names_lookup(bn, "com.anubee.aidl.IFoo", 2), "sendData"), "code 2 -> sendData");
    CHECK(binder_names_lookup(bn, "com.anubee.aidl.IFoo", 16777215) &&
          !strcmp(binder_names_lookup(bn, "com.anubee.aidl.IFoo", 16777215), "big"),
          "multi-byte encoded int");
    CHECK(!binder_names_lookup(bn, "com.anubee.aidl.IFoo", 3), "unknown code -> NULL");
    CHECK(!binder_names_lookup(bn, "com.anubee.aidl.NotAStub", 1), "non-Stub class ignored");
    binder_names_free(bn);

    bn = binder_names_new();
    CHECK(binder_names_add_jar(bn, jar, jlen) == 5, "jar: stored classes.dex indexed");
    CHECK(binder_names_count(bn) == 5, "count");
    binder_names_free(bn);

    // first entry deflated with a data descriptor (as real framework jars)
    bn = binder_names_new();
    CHECK(binder_names_add_jar(bn, ddjar, ddlen) == 5,
          "jar whose first entry uses a data descriptor: dex still found");
    binder_names_free(bn);

    bn = binder_names_new();
    CHECK(binder_names_add_dex(bn, dex, 40) == 0, "truncated dex -> 0, no crash");
    unsigned char bad[0x70]; memcpy(bad, dex, sizeof bad);
    memset(bad + 0x60, 0xff, 8);   // class_defs size/off out of range
    CHECK(binder_names_add_dex(bn, bad, sizeof bad) == 0, "out-of-range class_defs -> 0");
    binder_names_free(bn);
out:
    free(dex); free(jar); free(ddjar);
    printf("test_binder_api_parse: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
