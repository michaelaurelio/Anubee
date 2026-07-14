// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "modules/accessibility_detect_classify.h"

unsigned classify_accessibility(int touch_count, int granted)
{
    unsigned cat = 0;
    if (touch_count >= ACCESSIBILITY_DETECT_THRESHOLD)
        cat |= ACCESSIBILITY_DETECT_BURST_DETECTED;
    if (granted == 1)
        cat |= ACCESSIBILITY_DETECT_SERVICE_GRANTED;
    return cat;
}
