// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "modules/a11y_abuse_classify.h"

unsigned classify_a11y(int touch_count, int granted)
{
    unsigned cat = 0;
    if (touch_count >= A11Y_THRESHOLD)
        cat |= A11Y_BURST_DETECTED;
    if (granted == 1)
        cat |= A11Y_SERVICE_GRANTED;
    return cat;
}
