// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared target-arg CSV parser (anubee_parse_pid_list).
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "common/engine_args.h"

static int checks = 0, failures = 0;
#define CHECK_EQ(a, b, msg) do {                              \
    checks++;                                                 \
    if ((a) != (b)) { failures++;                             \
        printf("  FAIL: %s (got %d, want %d)\n", msg,        \
               (int)(a), (int)(b)); }                         \
} while (0)

int main(void)
{
    pid_t buf[64];

    // basic comma-separated list
    CHECK_EQ(anubee_parse_pid_list("10,20,30", buf, 64), 3, "csv count 3");
    CHECK_EQ(buf[0], 10, "csv[0]=10");
    CHECK_EQ(buf[1], 20, "csv[1]=20");
    CHECK_EQ(buf[2], 30, "csv[2]=30");

    // single value
    CHECK_EQ(anubee_parse_pid_list("42", buf, 64), 1, "single count");
    CHECK_EQ(buf[0], 42, "single value=42");

    // cap respected: max=2 on a 3-element list → only 2 written
    CHECK_EQ(anubee_parse_pid_list("1,2,3", buf, 2), 2, "cap at max=2");
    CHECK_EQ(buf[0], 1, "capped[0]=1");
    CHECK_EQ(buf[1], 2, "capped[1]=2");

    // empty / NULL
    CHECK_EQ(anubee_parse_pid_list("", buf, 64), 0, "empty csv");
    CHECK_EQ(anubee_parse_pid_list(NULL, buf, 64), 0, "null csv");

    // AUDIT.md #5: a csv longer than the internal 512-byte buffer now warns
    // on stderr (not asserted here) but must still return the PIDs that DO
    // fit ahead of the 512-byte cutoff, with no functional regression.
    {
        // 100 comma-joined 7-digit PIDs (1000000..1000099). The first entry
        // costs 7 bytes, every entry after costs 8 (",1000000"), so the
        // first 64 entries sum to exactly 7 + 63*8 = 511 bytes -- exactly
        // anubee_parse_pid_list's usable buffer size (sizeof(buf)-1) -- which
        // lands the truncation cut precisely on a comma boundary (verified:
        // no token is split mid-number).
        char oversized[900] = "";
        size_t off = 0;
        for (int i = 0; i < 100; i++) {
            off += (size_t)snprintf(oversized + off, sizeof(oversized) - off,
                                     i == 0 ? "%d" : ",%d", 1000000 + i);
        }

        pid_t big_buf[100];
        int got = anubee_parse_pid_list(oversized, big_buf, 100);
        CHECK_EQ(got, 64, "oversized csv: truncated at exactly 64 pre-cutoff PIDs");
        for (int i = 0; i < got; i++)
            CHECK_EQ(big_buf[i], 1000000 + i, "oversized csv: pre-cutoff PID value preserved");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
