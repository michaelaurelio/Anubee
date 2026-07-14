// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the pure accessibility-detect classification logic.
#include <linux/types.h>
#include <stdio.h>
#include "modules/accessibility_detect_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- classify_accessibility: at threshold, grant unknown -----------------------------
    unsigned c = classify_accessibility(ACCESSIBILITY_DETECT_THRESHOLD, -1);
    CHECK(c & ACCESSIBILITY_DETECT_BURST_DETECTED, "touch_count==threshold -> burst detected");
    CHECK(!(c & ACCESSIBILITY_DETECT_SERVICE_GRANTED), "grant unknown -> tag not set");

    // ---- classify_accessibility: above threshold, grant unknown ---------------------------
    c = classify_accessibility(ACCESSIBILITY_DETECT_THRESHOLD + 30, -1);
    CHECK(c & ACCESSIBILITY_DETECT_BURST_DETECTED, "touch_count>threshold -> burst detected");

    // ---- classify_accessibility: below threshold (defensive gate) --------------------------
    c = classify_accessibility(ACCESSIBILITY_DETECT_THRESHOLD - 1, 1);
    CHECK(!(c & ACCESSIBILITY_DETECT_BURST_DETECTED), "touch_count<threshold -> not detected even if granted");

    // ---- classify_accessibility: threshold + granted ---------------------------------------
    c = classify_accessibility(ACCESSIBILITY_DETECT_THRESHOLD, 1);
    CHECK(c & ACCESSIBILITY_DETECT_BURST_DETECTED,  "full burst -> detected");
    CHECK(c & ACCESSIBILITY_DETECT_SERVICE_GRANTED, "granted -> tag set");

    // ---- classify_accessibility: threshold, checked and NOT granted (distinct from unknown) -
    c = classify_accessibility(ACCESSIBILITY_DETECT_THRESHOLD, 0);
    CHECK(c & ACCESSIBILITY_DETECT_BURST_DETECTED, "burst still detected without grant");
    CHECK(!(c & ACCESSIBILITY_DETECT_SERVICE_GRANTED), "checked-but-not-granted -> tag not set");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
