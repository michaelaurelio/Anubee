// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "modules/ransomware_burst_classify.h"

int burst_distinct_count(const unsigned long long *hashes, int n)
{
    if (n <= 0)
        return 0;

    int distinct = 0;
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < i; j++) {
            if (hashes[j] == hashes[i]) { seen = 1; break; }
        }
        if (!seen) distinct++;
    }
    return distinct;
}

unsigned classify_burst(int touch_count, int distinct_count, int manage_ext_storage)
{
    unsigned cat = 0;
    if (touch_count >= BURST_THRESHOLD && distinct_count >= BURST_DISTINCT_MIN)
        cat |= RB_BURST_DETECTED;
    if (manage_ext_storage == 1)
        cat |= RB_MANAGE_EXT_STORAGE;
    return cat;
}
