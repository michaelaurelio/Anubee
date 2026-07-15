// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the pure massdelete-detect distinct-count and
// classification logic.
#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include "modules/massdelete_detect_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- burst_distinct_count: all-unique --------------------------------------
    char uniq[5][FILE_PATH_LEN] = {
        "/sdcard/DCIM/a.jpg", "/sdcard/DCIM/b.jpg", "/sdcard/DCIM/c.jpg",
        "/sdcard/DCIM/d.jpg", "/sdcard/DCIM/e.jpg",
    };
    CHECK(burst_distinct_count(uniq, 5) == 5, "5 unique paths -> distinct 5");

    // ---- burst_distinct_count: all-duplicate ------------------------------------
    char dup[20][FILE_PATH_LEN];
    for (int i = 0; i < 20; i++)
        strncpy(dup[i], "/sdcard/DCIM/same.jpg", FILE_PATH_LEN - 1);
    CHECK(burst_distinct_count(dup, 20) == 1, "20x same path -> distinct 1");

    // ---- burst_distinct_count: mixed (5 unique values, each repeated 4x) -------
    char mixed[20][FILE_PATH_LEN];
    for (int i = 0; i < 20; i++)
        snprintf(mixed[i], FILE_PATH_LEN, "/sdcard/DCIM/f%d.jpg", i % 5);
    CHECK(burst_distinct_count(mixed, 20) == 5, "5 values x4 repeats -> distinct 5");

    // ---- burst_distinct_count: n == 0 --------------------------------------------
    CHECK(burst_distinct_count(uniq, 0) == 0, "n == 0 -> distinct 0");

    // ---- burst_distinct_count: negative n (defensive) ----------------------------
    CHECK(burst_distinct_count(uniq, -1) == 0, "negative n -> distinct 0 (defensive)");

    // ---- classify_burst: at the distinct floor, threshold met -------------------
    unsigned c = classify_burst(MASSDELETE_DETECT_THRESHOLD, MASSDELETE_DETECT_DISTINCT_MIN, -1);
    CHECK(c & MASSDELETE_DETECT_BURST_DETECTED, "touch>=threshold, distinct==floor -> burst detected");
    CHECK(!(c & MASSDELETE_DETECT_MANAGE_EXT_STORAGE), "manage_ext_storage unknown -> tag not set");

    // ---- classify_burst: just under the distinct floor ---------------------------
    c = classify_burst(MASSDELETE_DETECT_THRESHOLD, MASSDELETE_DETECT_DISTINCT_MIN - 1, -1);
    CHECK(!(c & MASSDELETE_DETECT_BURST_DETECTED), "distinct just under floor -> not detected");

    // ---- classify_burst: touch_count below threshold (defensive gate) -----------
    c = classify_burst(MASSDELETE_DETECT_THRESHOLD - 1, MASSDELETE_DETECT_THRESHOLD, -1);
    CHECK(!(c & MASSDELETE_DETECT_BURST_DETECTED), "touch_count under threshold -> not detected even if distinct is high");

    // ---- classify_burst: MANAGE_EXTERNAL_STORAGE granted, combined with burst ---
    c = classify_burst(MASSDELETE_DETECT_THRESHOLD, MASSDELETE_DETECT_THRESHOLD, 1);
    CHECK(c & MASSDELETE_DETECT_BURST_DETECTED,     "full distinct burst -> detected");
    CHECK(c & MASSDELETE_DETECT_MANAGE_EXT_STORAGE, "manage_ext_storage granted -> tag set");

    // ---- classify_burst: checked and NOT granted (distinct from unknown) --------
    c = classify_burst(MASSDELETE_DETECT_THRESHOLD, MASSDELETE_DETECT_THRESHOLD, 0);
    CHECK(!(c & MASSDELETE_DETECT_MANAGE_EXT_STORAGE), "manage_ext_storage checked-but-denied -> tag not set");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
