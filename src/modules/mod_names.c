// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "modules/mod_names.h"

int mod_dedupe_names(const char *names[], int n, void (*on_dup)(const char *name))
{
    int out = 0;
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int j = 0; j < out; j++)
            if (strcmp(names[j], names[i]) == 0) { seen = 1; break; }
        if (seen) {
            if (on_dup) on_dup(names[i]);
            continue;
        }
        names[out++] = names[i];
    }
    return out;
}
