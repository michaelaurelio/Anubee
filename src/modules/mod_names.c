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

int mod_expand_presets(const char *names[], int n, int cap,
                       const char *const *all, int nall,
                       int (*is_loud)(const char *name))
{
    const char *out[64];
    int m = 0;
    if (cap > 64) cap = 64;
    for (int i = 0; i < n; i++) {
        if (strcmp(names[i], MOD_PRESET_TRIAGE)) {
            if (m == cap) return -1;
            out[m++] = names[i];
            continue;
        }
        for (int j = 0; j < nall; j++) {
            if (is_loud(all[j])) continue;
            if (m == cap) return -1;
            out[m++] = all[j];
        }
    }
    for (int i = 0; i < m; i++) names[i] = out[i];
    return m;
}
