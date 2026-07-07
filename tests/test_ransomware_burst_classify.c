// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the pure ransomware-burst distinct-count and
// classification logic.
#include <stdio.h>
#include "modules/ransomware_burst_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- burst_distinct_count: all-unique --------------------------------------
    unsigned long long uniq[5] = { 1, 2, 3, 4, 5 };
    CHECK(burst_distinct_count(uniq, 5) == 5, "5 unique hashes -> distinct 5");

    // ---- burst_distinct_count: all-duplicate ------------------------------------
    unsigned long long dup[20];
    for (int i = 0; i < 20; i++) dup[i] = 42;
    CHECK(burst_distinct_count(dup, 20) == 1, "20x same hash -> distinct 1");

    // ---- burst_distinct_count: mixed (5 unique values, each repeated 4x) -------
    unsigned long long mixed[20];
    for (int i = 0; i < 20; i++) mixed[i] = (unsigned long long)(i % 5);
    CHECK(burst_distinct_count(mixed, 20) == 5, "5 values x4 repeats -> distinct 5");

    // ---- burst_distinct_count: n == 0 --------------------------------------------
    CHECK(burst_distinct_count(uniq, 0) == 0, "n == 0 -> distinct 0");

    // ---- burst_distinct_count: negative n (defensive) ----------------------------
    CHECK(burst_distinct_count(uniq, -1) == 0, "negative n -> distinct 0 (defensive)");

    // ---- classify_burst: at the distinct floor, threshold met -------------------
    unsigned c = classify_burst(BURST_THRESHOLD, BURST_DISTINCT_MIN, -1);
    CHECK(c & RB_BURST_DETECTED, "touch>=threshold, distinct==floor -> burst detected");
    CHECK(!(c & RB_MANAGE_EXT_STORAGE), "manage_ext_storage unknown -> tag not set");

    // ---- classify_burst: just under the distinct floor ---------------------------
    c = classify_burst(BURST_THRESHOLD, BURST_DISTINCT_MIN - 1, -1);
    CHECK(!(c & RB_BURST_DETECTED), "distinct just under floor -> not detected");

    // ---- classify_burst: touch_count below threshold (defensive gate) -----------
    c = classify_burst(BURST_THRESHOLD - 1, BURST_THRESHOLD, -1);
    CHECK(!(c & RB_BURST_DETECTED), "touch_count under threshold -> not detected even if distinct is high");

    // ---- classify_burst: MANAGE_EXTERNAL_STORAGE granted, combined with burst ---
    c = classify_burst(BURST_THRESHOLD, BURST_THRESHOLD, 1);
    CHECK(c & RB_BURST_DETECTED,     "full distinct burst -> detected");
    CHECK(c & RB_MANAGE_EXT_STORAGE, "manage_ext_storage granted -> tag set");

    // ---- classify_burst: checked and NOT granted (distinct from unknown) --------
    c = classify_burst(BURST_THRESHOLD, BURST_THRESHOLD, 0);
    CHECK(!(c & RB_MANAGE_EXT_STORAGE), "manage_ext_storage checked-but-denied -> tag not set");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
