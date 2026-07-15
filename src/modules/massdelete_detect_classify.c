// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <string.h>
#include "modules/massdelete_detect_classify.h"

int burst_distinct_count(const char paths[][FILE_PATH_LEN], int n)
{
    if (n <= 0)
        return 0;

    int distinct = 0;
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < i; j++) {
            if (strncmp(paths[j], paths[i], FILE_PATH_LEN) == 0) { seen = 1; break; }
        }
        if (!seen) distinct++;
    }
    return distinct;
}

unsigned classify_burst(int touch_count, int distinct_count, int manage_ext_storage)
{
    unsigned cat = 0;
    if (touch_count >= MASSDELETE_DETECT_THRESHOLD && distinct_count >= MASSDELETE_DETECT_DISTINCT_MIN)
        cat |= MASSDELETE_DETECT_BURST_DETECTED;
    if (manage_ext_storage == 1)
        cat |= MASSDELETE_DETECT_MANAGE_EXT_STORAGE;
    return cat;
}
