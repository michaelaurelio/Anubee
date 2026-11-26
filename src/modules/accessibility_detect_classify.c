// SPDX-License-Identifier: GPL-2.0
// IAccessibilityServiceConnection method -> abuse category. See the header.
#include <stddef.h>
#include <string.h>
#include "modules/accessibility_detect_classify.h"

static const struct { const char *method; int cat; } k_methods[] = {
    { "findAccessibilityNodeInfoByAccessibilityId", A11Y_SCREEN_READ },
    { "findAccessibilityNodeInfosByText",           A11Y_SCREEN_READ },
    { "findAccessibilityNodeInfosByViewId",         A11Y_SCREEN_READ },
    { "findFocus",                                  A11Y_SCREEN_READ },
    { "focusSearch",                                A11Y_SCREEN_READ },
    { "getWindow",                                  A11Y_SCREEN_READ },
    { "getWindows",                                 A11Y_SCREEN_READ },
    { "performAccessibilityAction",                 A11Y_ACTION },
    { "dispatchGesture",                            A11Y_GESTURE },
    { "sendGesture",                                A11Y_GESTURE },
    { "performGlobalAction",                        A11Y_GLOBAL_ACTION },
    { "takeScreenshot",                             A11Y_SCREENSHOT },
    { "takeScreenshotOfWindow",                     A11Y_SCREENSHOT },
    { "switchToInputMethod",                        A11Y_INPUT_METHOD },
    { "setInputMethodEnabled",                      A11Y_INPUT_METHOD },
    { "setSoftKeyboardShowMode",                    A11Y_INPUT_METHOD },
};

static const char *const k_names[A11Y_CAT_N] = {
    "other", "screen_read", "action", "gesture", "global_action", "screenshot", "input_method",
};

int a11y_classify_method(const char *method)
{
    if (!method) return A11Y_OTHER;
    for (size_t i = 0; i < sizeof k_methods / sizeof k_methods[0]; i++)
        if (!strcmp(method, k_methods[i].method))
            return k_methods[i].cat;
    return A11Y_OTHER;
}

const char *a11y_category_name(int cat)
{
    return cat > 0 && cat < A11Y_CAT_N ? k_names[cat] : k_names[A11Y_OTHER];
}

int a11y_category_alerts(int cat)
{
    return cat > A11Y_OTHER && cat < A11Y_CAT_N;
}
