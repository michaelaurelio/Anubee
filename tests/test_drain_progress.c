// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the pure half of common/drain_progress.h (no .c needed,
// same rationale as test_snapshot_gate.c): all percentage/ETA/formatting logic
// is static inline so it is testable without a queue, a worker or a terminal.
#include "common/drain_progress.h"

#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)
#define CHECK_STR(got, want, msg) do { \
    checks++; \
    if (strcmp((got), (want)) != 0) { failures++; \
        printf("  FAIL: %s\n    want: '%s'\n    got:  '%s'\n", msg, want, got); } \
} while (0)

#define NS_MS(x) ((unsigned long long)(x) * 1000000ULL)
#define NS_S(x)  ((unsigned long long)(x) * 1000000000ULL)

int main(void)
{
    char buf[64];

    // --- drain_should_show: 300ms trigger, zero-backlog guard ---
    CHECK(drain_should_show(0, 1000) == 0,          "show: 0ms -> no");
    CHECK(drain_should_show(NS_MS(299), 1000) == 0, "show: 299ms -> no");
    CHECK(drain_should_show(NS_MS(300), 1000) == 1, "show: 300ms -> yes");
    CHECK(drain_should_show(NS_S(60), 1000) == 1,   "show: 60s -> yes");
    CHECK(drain_should_show(NS_S(60), 0) == 0,      "show: zero backlog -> no");

    // --- drain_pct: bytes drained / bytes at begin, clamped ---
    CHECK(drain_pct(100, 100) == 0,   "pct: nothing drained -> 0");
    CHECK(drain_pct(100, 50)  == 50,  "pct: half drained -> 50");
    CHECK(drain_pct(100, 0)   == 100, "pct: fully drained -> 100");
    CHECK(drain_pct(0, 0)     == 100, "pct: empty backlog -> 100");
    CHECK(drain_pct(100, 200) == 0,   "pct: used > total clamps to 0");
    CHECK(drain_pct(3, 2)     == 33,  "pct: truncates, no rounding");

    // --- drain_eta_secs: -1 = suppress ---
    CHECK(drain_eta_secs(100, 50, NS_MS(999)) == -1, "eta: <1s -> suppress");
    CHECK(drain_eta_secs(100, 100, NS_S(2))   == -1, "eta: no progress yet -> suppress");
    CHECK(drain_eta_secs(100, 0, NS_S(2))     == 0,  "eta: done -> 0");
    // 50 of 100 bytes in 2s = 25 B/s; 50 left => 2s
    CHECK(drain_eta_secs(100, 50, NS_S(2))    == 2,  "eta: half done in 2s -> 2s");
    // 25 of 100 bytes in 1s = 25 B/s; 75 left => 3s
    CHECK(drain_eta_secs(100, 75, NS_S(1))    == 3,  "eta: quarter done in 1s -> 3s");
    CHECK(drain_eta_secs(100, 200, NS_S(2))   == -1, "eta: used > total -> suppress");

    // --- drain_fmt_count: thousands separators ---
    drain_fmt_count(0, buf, sizeof buf);       CHECK_STR(buf, "0",         "count: 0");
    drain_fmt_count(7, buf, sizeof buf);       CHECK_STR(buf, "7",         "count: 7");
    drain_fmt_count(999, buf, sizeof buf);     CHECK_STR(buf, "999",       "count: 999");
    drain_fmt_count(1000, buf, sizeof buf);    CHECK_STR(buf, "1,000",     "count: 1000");
    drain_fmt_count(8192, buf, sizeof buf);    CHECK_STR(buf, "8,192",     "count: 8192");
    drain_fmt_count(200412, buf, sizeof buf);  CHECK_STR(buf, "200,412",   "count: 200412");
    drain_fmt_count(1234567, buf, sizeof buf); CHECK_STR(buf, "1,234,567", "count: 1234567");

    // --- drain_fmt_duration ---
    drain_fmt_duration(0, buf, sizeof buf);    CHECK_STR(buf, "0s",     "dur: 0");
    drain_fmt_duration(8, buf, sizeof buf);    CHECK_STR(buf, "8s",     "dur: 8s");
    drain_fmt_duration(59, buf, sizeof buf);   CHECK_STR(buf, "59s",    "dur: 59s");
    drain_fmt_duration(60, buf, sizeof buf);   CHECK_STR(buf, "1m0s",   "dur: 60s");
    drain_fmt_duration(72, buf, sizeof buf);   CHECK_STR(buf, "1m12s",  "dur: 72s");
    drain_fmt_duration(151, buf, sizeof buf);  CHECK_STR(buf, "2m31s",  "dur: 151s");
    drain_fmt_duration(3661, buf, sizeof buf); CHECK_STR(buf, "1h1m1s", "dur: 3661s");
    drain_fmt_duration(-5, buf, sizeof buf);   CHECK_STR(buf, "0s",     "dur: negative clamps");

    printf("%s: %d checks, %d failures\n",
           failures ? "FAIL" : "ok", checks, failures);
    return failures ? 1 : 0;
}
