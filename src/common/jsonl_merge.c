// SPDX-License-Identifier: GPL-2.0
#include "common/jsonl_merge.h"

#include <stdio.h>

int jsonl_merge(const char *dst_path, const char *const *src_paths, int n_srcs)
{
    FILE *dst = fopen(dst_path, "w");
    if (!dst)
        return -1;

    int merged = 0;
    int werr = 0;
    char buf[65536];
    for (int i = 0; i < n_srcs; i++) {
        FILE *src = fopen(src_paths[i], "r");
        if (!src)
            continue;   // engine not requested / setup failed - skip, not an error
        char last = '\n';   // AUDIT.md #3: assume "start of file" needs no separator
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
            if (fwrite(buf, 1, n, dst) != n)
                werr = 1;
            last = buf[n - 1];
        }
        fclose(src);
        // A source without a trailing newline would otherwise fuse its last
        // record with the next source's first line into one corrupt JSONL
        // line (AUDIT.md #3) - insert the missing separator.
        if (last != '\n' && fputc('\n', dst) == EOF)
            werr = 1;
        merged++;
    }
    if (fclose(dst) != 0)
        werr = 1;
    return werr ? -1 : merged;
}
