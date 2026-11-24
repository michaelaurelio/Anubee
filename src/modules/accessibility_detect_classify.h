// SPDX-License-Identifier: GPL-2.0
// Pure classification for `anubee mod accessibility-detect` (host-tested):
// map an android.accessibilityservice.IAccessibilityServiceConnection method
// -- the channel an app's own AccessibilityService uses to talk to the system,
// so a call on it means the service is active -- to the abuse it enables.
#ifndef __ANUBEE_ACCESSIBILITY_DETECT_CLASSIFY_H
#define __ANUBEE_ACCESSIBILITY_DETECT_CLASSIFY_H

#define A11Y_SERVICE_IFACE "android.accessibilityservice.IAccessibilityServiceConnection"

enum a11y_category {
    A11Y_OTHER = 0,       // counted, not alerted (setServiceInfo, magnification...)
    A11Y_SCREEN_READ,     // read other apps' UI: node/window queries (credential/OTP theft)
    A11Y_ACTION,          // act on other apps' UI nodes: click, set text (ATS fraud)
    A11Y_GESTURE,         // inject touch gestures
    A11Y_GLOBAL_ACTION,   // back/home/recents/notifications (escape uninstall/settings screens)
    A11Y_SCREENSHOT,      // capture the screen
    A11Y_INPUT_METHOD,    // switch/enable the keyboard (keylogging takeover)
    A11Y_CAT_N
};

int a11y_classify_method(const char *method);
const char *a11y_category_name(int cat);
int a11y_category_alerts(int cat);

#endif /* __ANUBEE_ACCESSIBILITY_DETECT_CLASSIFY_H */
