// test_stack_snapshot.c — host unit test for ares_stack_snapshot_emit_json.
// Links: stack_snapshot.c emit.c trace_schema.c
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/types.h>
#include "common/stack_snapshot.h"
#include "common/emit.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } \
} while (0)

int main(void)
{
    struct ares_stack_snapshot s;
    memset(&s, 0, sizeof(s));
    s.h.pid    = 1234;
    s.h.tid    = 5678;
    s.stack_id = 0xdeadbeefcafe0001ULL;
    s.pc       = 0xaaaabbbbULL;
    s.sp       = 0xccccddddULL;
    s.fp       = 0xeeee0000ULL;
    s.lr       = 0xffff1111ULL;
    for (int i = 0; i < 31; i++)
        s.regs[i] = 0x100ULL + i;
    /* write two bytes of stack, mark them valid */
    s.snap[0] = 0xab; s.snap[1] = 0xcd;
    s.snap_len = 2;
    s.truncated = 0;

    struct jbuf j = {0};
    ares_stack_snapshot_emit_json(&j, &s);

    CHECK(j.b && j.len > 0,              "jbuf populated");
    CHECK(strstr(j.b, "\"type\":\"stack\""),  "type:stack present");
    CHECK(strstr(j.b, "1234"),           "pid present");
    CHECK(strstr(j.b, "5678"),           "tid present");
    CHECK(strstr(j.b, "\"regs\":["),     "regs array present");
    CHECK(strstr(j.b, "\"truncated\":0"), "truncated=0 present");
    CHECK(strstr(j.b, "\"snapshot\":\""), "snapshot field present");
    /* base64 of 0xab 0xcd = "q80=" */
    CHECK(strstr(j.b, "q80="),           "base64 snap correct");
    CHECK(j.b[j.len - 1] == '\n',        "trailing newline");

    /* truncated=1 path */
    struct jbuf j2 = {0};
    s.truncated = 1;
    ares_stack_snapshot_emit_json(&j2, &s);
    CHECK(j2.b && strstr(j2.b, "\"truncated\":1"), "truncated=1 present");

    /* W3-window: read side must serialise ANY snap_len, not just the legacy
     * 8K/32K tiers. 16384 is deliberately not a former tier size. */
    struct jbuf j3 = {0};
    struct ares_stack_snapshot s3;
    memset(&s3, 0, sizeof(s3));
    s3.h.pid   = 1234;
    s3.snap_len = 16384;
    s3.snap[0] = 0x01;
    s3.snap[16383] = 0x02;
    ares_stack_snapshot_emit_json(&j3, &s3);
    CHECK(j3.b && strstr(j3.b, "\"snap_len\":16384"), "non-tier snap_len serialises");
    CHECK(strstr(j3.b, "\"snapshot\":\""),            "non-tier snapshot field present");
    free(j3.b);

    free(j.b);
    free(j2.b);
    printf("test_stack_snapshot: ok\n");
    return 0;
}
