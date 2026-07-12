// SPDX-License-Identifier: GPL-2.0
#include "common/jsonl_merge.h"

#include <stdio.h>

int jsonl_merge(const char *dst_path, const char *const *src_paths, int n_srcs)
{
    FILE *dst = fopen(dst_path, "w");
    if (!dst)
        return -1;

    int merged = 0;
    char buf[65536];
    for (int i = 0; i < n_srcs; i++) {
        FILE *src = fopen(src_paths[i], "r");
        if (!src)
            continue;   // engine not requested / setup failed - skip, not an error
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            fwrite(buf, 1, n, dst);
        fclose(src);
        merged++;
    }
    fclose(dst);
    return merged;
}
