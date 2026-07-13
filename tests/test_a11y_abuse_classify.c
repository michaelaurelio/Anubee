// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the pure a11y-abuse classification logic.
#include <linux/types.h>
#include <stdio.h>
#include "modules/a11y_abuse_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- classify_a11y: at threshold, grant unknown -----------------------------
    unsigned c = classify_a11y(A11Y_THRESHOLD, -1);
    CHECK(c & A11Y_BURST_DETECTED, "touch_count==threshold -> burst detected");
    CHECK(!(c & A11Y_SERVICE_GRANTED), "grant unknown -> tag not set");

    // ---- classify_a11y: above threshold, grant unknown ---------------------------
    c = classify_a11y(A11Y_THRESHOLD + 30, -1);
    CHECK(c & A11Y_BURST_DETECTED, "touch_count>threshold -> burst detected");

    // ---- classify_a11y: below threshold (defensive gate) --------------------------
    c = classify_a11y(A11Y_THRESHOLD - 1, 1);
    CHECK(!(c & A11Y_BURST_DETECTED), "touch_count<threshold -> not detected even if granted");

    // ---- classify_a11y: threshold + granted ---------------------------------------
    c = classify_a11y(A11Y_THRESHOLD, 1);
    CHECK(c & A11Y_BURST_DETECTED,  "full burst -> detected");
    CHECK(c & A11Y_SERVICE_GRANTED, "granted -> tag set");

    // ---- classify_a11y: threshold, checked and NOT granted (distinct from unknown) -
    c = classify_a11y(A11Y_THRESHOLD, 0);
    CHECK(c & A11Y_BURST_DETECTED, "burst still detected without grant");
    CHECK(!(c & A11Y_SERVICE_GRANTED), "checked-but-not-granted -> tag not set");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
