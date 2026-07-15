// SPDX-License-Identifier: GPL-2.0
// Host unit test for the vendored SHA-256. Pins the NIST FIPS 180-4 vectors so
// a miscompiled or mis-vendored implementation cannot reach the modcmp record,
// where a wrong digest would silently mislabel a library's integrity.
#include "common/sha256.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0, failures = 0;
#define EQ(got, want, msg) do {                                       \
    checks++;                                                         \
    if (strcmp((got), (want)) != 0) { failures++;                     \
        printf("  FAIL: %s\n    got:  %s\n    want: %s\n",            \
               msg, (got), (want)); }                                 \
} while (0)

// One-shot over the streaming API. Lives here rather than in sha256.h because
// no production caller wants it: dump --check digests several segments into one
// hash and drives init/update/final_hex directly.
static void hx(const void *d, size_t n, char out[65])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, d, n);
    sha256_final_hex(&c, out);
}

int main(void)
{
    char h[65];

    // NIST FIPS 180-4, empty input.
    hx("", 0, h);
    EQ(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty");

    // NIST FIPS 180-4 vector 1: "abc".
    hx("abc", 3, h);
    EQ(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");

    // NIST FIPS 180-4 vector 2: 448-bit message (exercises the length-pad edge:
    // 56 bytes leaves no room for the 8-byte length, forcing a second block).
    hx("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, h);
    EQ(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "448-bit");

    // Exactly one block (64 bytes) - padding must spill into a whole extra block.
    char blk[64];
    memset(blk, 'a', sizeof(blk));
    hx(blk, sizeof(blk), h);
    EQ(h, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", "64-byte block");

    // 1,000,000 x 'a' - NIST long vector; proves multi-block streaming across
    // many update() calls, which is how dump --check feeds it segment by segment.
    char *big = malloc(1000000);
    if (!big) { printf("  FAIL: alloc\n"); return 1; }
    memset(big, 'a', 1000000);
    struct sha256_ctx c;
    sha256_init(&c);
    for (int i = 0; i < 1000; i++)
        sha256_update(&c, big + i * 1000, 1000);   // 1000 chunked updates
    sha256_final_hex(&c, h);
    EQ(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "1M x a, chunked");
    free(big);

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
