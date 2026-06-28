// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared target-arg CSV parser (ares_parse_pid_list).
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
    CHECK_EQ(ares_parse_pid_list("10,20,30", buf, 64), 3, "csv count 3");
    CHECK_EQ(buf[0], 10, "csv[0]=10");
    CHECK_EQ(buf[1], 20, "csv[1]=20");
    CHECK_EQ(buf[2], 30, "csv[2]=30");

    // single value
    CHECK_EQ(ares_parse_pid_list("42", buf, 64), 1, "single count");
    CHECK_EQ(buf[0], 42, "single value=42");

    // cap respected: max=2 on a 3-element list → only 2 written
    CHECK_EQ(ares_parse_pid_list("1,2,3", buf, 2), 2, "cap at max=2");
    CHECK_EQ(buf[0], 1, "capped[0]=1");
    CHECK_EQ(buf[1], 2, "capped[1]=2");

    // empty / NULL
    CHECK_EQ(ares_parse_pid_list("", buf, 64), 0, "empty csv");
    CHECK_EQ(ares_parse_pid_list(NULL, buf, 64), 0, "null csv");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
