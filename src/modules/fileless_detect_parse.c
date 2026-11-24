// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include "modules/fileless_detect_parse.h"

const char *fl_kind_name(int kind)
{
    switch (kind) {
    case FL_KIND_ANON_MMAP:   return "anon_exec_mmap";
    case FL_KIND_MPROTECT_EXEC: return "mprotect_exec";
    case FL_KIND_MEMFD_EXEC:  return "memfd_exec";
    default:                  return "unknown";
    }
}

int fl_maps_region(const char *maps, unsigned long addr, unsigned long *start,
                   unsigned long *end, char perms[8], char *name, size_t cap)
{
    if (!maps) return 0;
    for (const char *p = maps; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        unsigned long s, e;
        char pm[8];
        int off = 0;
        if (sscanf(p, "%lx-%lx %7s %*x %*x:%*x %*u%n", &s, &e, pm, &off) == 3 &&
            off > 0 && addr >= s && addr < e) {
            if (start) *start = s;
            if (end)   *end = e;
            if (perms) snprintf(perms, 8, "%s", pm);
            if (name && cap) {
                const char *n = p + off;
                const char *lim = p + ll;
                while (n < lim && *n == ' ') n++;
                size_t nlen = (size_t)(lim - n);
                while (nlen && n[nlen - 1] == ' ') nlen--;
                const char *pre[] = { "[anon_shmem:", "[anon:" };
                for (int i = 0; i < 2; i++) {
                    size_t pl = strlen(pre[i]);
                    if (nlen > pl && !strncmp(n, pre[i], pl) && n[nlen - 1] == ']') {
                        n += pl;
                        nlen -= pl + 1;
                        break;
                    }
                }
                snprintf(name, cap, "%.*s", (int)nlen, n);
            }
            return 1;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

int fl_name_is_art(const char *name)
{
    if (!name) return 0;
    if (!strncmp(name, "dalvik-", 7)) return 1;
    const char *m = strstr(name, "memfd:");
    if (!m || (m != name && !(m == name + 1 && name[0] == '/'))) return 0;
    m += 6;
    return !strncmp(m, "jit-cache", 9) || !strncmp(m, "jit-zygote-cache", 16);
}

const char *fl_content_of(const unsigned char *b, size_t n)
{
    if (!b || n == 0) return NULL;
    if (n >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') return "elf";
    for (size_t i = 0; i < n; i++)
        if (b[i]) return "data";
    return "zero";
}
