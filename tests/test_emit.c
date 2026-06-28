// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared JSON buffer serializer and ares_sink.
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
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } } while (0)

// Read the entire contents of a file into a malloc'd buffer (NUL-terminated).
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

    free(j.b); j = (struct jbuf){0};

    // GA1 regression: simulate OOM realloc by pre-poisoning err, then verify
    // that jb_* writers are no-ops and the buffer is not written past cap.
    {
        struct jbuf bad = {0};
        jb_s(&bad, "seed");           // normal first allocation
        size_t saved_cap = bad.cap;
        bad.err = 1;                  // synthesise the post-OOM-grow state
        size_t saved_len = bad.len;
        jb_s(&bad, "SHOULD_NOT_APPEAR");
        jb_c(&bad, 'X');
        CHECK(bad.len == saved_len,   "oom: len stays fixed");
        CHECK(bad.cap == saved_cap,   "oom: cap stays fixed");
        CHECK(memcmp(bad.b, "seed", 4) == 0, "oom: existing content intact");
        free(bad.b);
    }

    // ares_sink: JSONL mode — each record on its own line, no array framing.
    {
        const char *path = "/tmp/test_sink_jsonl.jsonl";
        struct ares_sink s = {0};
        CHECK(ares_sink_open(&s, path, "event", 1) == 0, "sink jsonl open");
        jb_s(&s.jb, "{\"a\":1}"); ares_sink_emit(&s);
        jb_s(&s.jb, "{\"b\":2}"); ares_sink_emit(&s);
        ares_sink_close(&s);
        CHECK(s.count == 2, "sink jsonl count");
        char *got = slurp(path);
        CHECK(got && strcmp(got, "{\"a\":1}\n{\"b\":2}\n") == 0, "sink jsonl content");
        free(got);
    }

    // ares_sink: array mode — JSON array with comma-sep records.
    {
        const char *path = "/tmp/test_sink_array.json";
        struct ares_sink s = {0};
        CHECK(ares_sink_open(&s, path, "syscall", 0) == 0, "sink array open");
        jb_s(&s.jb, "{\"x\":1}"); ares_sink_emit(&s);
        jb_s(&s.jb, "{\"x\":2}"); ares_sink_emit(&s);
        ares_sink_close(&s);
        CHECK(s.count == 2, "sink array count");
        char *got = slurp(path);
        CHECK(got && strcmp(got, "[\n  {\"x\":1},\n  {\"x\":2}\n]\n") == 0, "sink array content");
        free(got);
    }

    // GA3: write errors latch instead of vanishing silently.
    {
        char tiny[16];
        struct ares_sink s = {0};
        s.f = fmemopen(tiny, sizeof tiny, "w");
        s.jsonl = 1; s.path = "<mem>"; s.noun = "event";
        CHECK(s.f != NULL, "ga3: fmemopen");
        for (int i = 0; i < 10; i++) { jb_s(&s.jb, "{\"x\":1234567890}"); ares_sink_emit(&s); }
        ares_sink_flush(&s);  // force the overflow through the flush path too
        CHECK(s.werr != 0, "ga3: write error latched on overflow");
        fclose(s.f); free(s.jb.b);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
