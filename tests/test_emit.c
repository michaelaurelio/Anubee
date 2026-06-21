// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared JSON buffer serializer. Pins the exact byte
// output so the heimdall repoint is provably behavior-preserving.
#include "common/emit.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0, failures = 0;
#define CHECK_STR(j, want, msg) do {                                        \
    checks++;                                                               \
    if ((j).len != strlen(want) || memcmp((j).b, want, (j).len) != 0) {     \
        failures++;                                                         \
        printf("  FAIL: %s\n    got: %.*s\n    want: %s\n",                 \
               msg, (int)(j).len, (j).b, want);                            \
    }                                                                       \
} while (0)

int main(void)
{
    struct jbuf j = {0};

    j.len = 0; jb_u64(&j, 0);            CHECK_STR(j, "0", "u64 zero");
    j.len = 0; jb_u64(&j, 4096);         CHECK_STR(j, "4096", "u64");
    j.len = 0; jb_i64(&j, -1);           CHECK_STR(j, "-1", "i64 neg");
    j.len = 0; jb_i64(&j, 42);           CHECK_STR(j, "42", "i64 pos");
    j.len = 0; jb_hex(&j, 0xdeadbeef);   CHECK_STR(j, "0xdeadbeef", "hex");
    j.len = 0; jb_hex(&j, 0);            CHECK_STR(j, "0x0", "hex zero");
    j.len = 0; jb_s(&j, "ab"); jb_c(&j, 'c'); CHECK_STR(j, "abc", "s+c");

    // Escaping: quote, backslash, control chars -> \uXXXX.
    j.len = 0; jb_esc(&j, "a\"b\\c\nd\te"); CHECK_STR(j, "a\\\"b\\\\c\\nd\\te", "esc");
    j.len = 0; jb_esc(&j, "\x01");          CHECK_STR(j, "\\u0001", "esc ctrl");

    // Base64 with each padding length.
    j.len = 0; jb_b64(&j, (const unsigned char *)"abc", 3); CHECK_STR(j, "YWJj", "b64 0pad");
    j.len = 0; jb_b64(&j, (const unsigned char *)"ab", 2);  CHECK_STR(j, "YWI=", "b64 1pad");
    j.len = 0; jb_b64(&j, (const unsigned char *)"a", 1);   CHECK_STR(j, "YQ==", "b64 2pad");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
