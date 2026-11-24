// SPDX-License-Identifier: GPL-2.0
// Host unit tests for accessibility-detect's method -> abuse-category mapping.
// Method names are android.accessibilityservice.IAccessibilityServiceConnection
// methods as named from the device's framework jar (binder_api_parse.c).
#include <stdio.h>
#include <string.h>
#include "modules/accessibility_detect_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

#define IS(m, cat) CHECK(a11y_classify_method(m) == (cat), m " -> " #cat)

int main(void)
{
    IS("findAccessibilityNodeInfoByAccessibilityId", A11Y_SCREEN_READ);
    IS("findAccessibilityNodeInfosByText",           A11Y_SCREEN_READ);
    IS("findAccessibilityNodeInfosByViewId",         A11Y_SCREEN_READ);
    IS("findFocus",                                  A11Y_SCREEN_READ);
    IS("focusSearch",                                A11Y_SCREEN_READ);
    IS("getWindow",                                  A11Y_SCREEN_READ);
    IS("getWindows",                                 A11Y_SCREEN_READ);
    IS("performAccessibilityAction",                 A11Y_ACTION);
    IS("dispatchGesture",                            A11Y_GESTURE);
    IS("sendGesture",                                A11Y_GESTURE);
    IS("performGlobalAction",                        A11Y_GLOBAL_ACTION);
    IS("takeScreenshot",                             A11Y_SCREENSHOT);
    IS("takeScreenshotOfWindow",                     A11Y_SCREENSHOT);
    IS("switchToInputMethod",                        A11Y_INPUT_METHOD);
    IS("setInputMethodEnabled",                      A11Y_INPUT_METHOD);
    IS("setSoftKeyboardShowMode",                    A11Y_INPUT_METHOD);
    IS("setServiceInfo",                             A11Y_OTHER);
    IS("getMagnificationConfig",                     A11Y_OTHER);
    CHECK(a11y_classify_method(NULL) == A11Y_OTHER, "NULL (unnamed code) -> other");

    CHECK(a11y_category_alerts(A11Y_SCREEN_READ) && a11y_category_alerts(A11Y_SCREENSHOT) &&
          !a11y_category_alerts(A11Y_OTHER), "other is counted, never alerted");
    CHECK(!strcmp(a11y_category_name(A11Y_GLOBAL_ACTION), "global_action") &&
          !strcmp(a11y_category_name(A11Y_SCREEN_READ), "screen_read") &&
          !strcmp(a11y_category_name(A11Y_OTHER), "other"), "category names");
    CHECK(!strcmp(a11y_category_name(-1), "other") && !strcmp(a11y_category_name(A11Y_CAT_N), "other"),
          "out-of-range -> other");

    printf("test_accessibility_detect_classify: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
