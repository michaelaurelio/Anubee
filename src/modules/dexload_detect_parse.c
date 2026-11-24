// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "modules/dexload_detect_parse.h"
#include "common/sha256.h"

static int is_digit(unsigned char c) { return c >= '0' && c <= '9'; }

int dl_kind_of(const unsigned char *b, size_t n)
{
    if (!b || n < 4) return DL_NONE;
    if (b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') return DL_ELF;
    if (b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4) return DL_ZIP;
    if (!memcmp(b, "cdex", 4)) return DL_CDEX;
    if (!memcmp(b, "dex\n", 4) && n >= 8 &&
        is_digit(b[4]) && is_digit(b[5]) && is_digit(b[6]) && b[7] == 0)
        return DL_DEX;
    return DL_NONE;
}

const char *dl_kind_name(int kind)
{
    switch (kind) {
    case DL_DEX:  return "dex";
    case DL_CDEX: return "cdex";
    case DL_ZIP:  return "zip";
    case DL_ELF:  return "elf";
    default:      return "none";
    }
}

const char *dl_kind_ext(int kind)
{
    return kind == DL_ELF ? "so" : dl_kind_name(kind);
}

int dl_drop_alerts(int kind)
{
    return kind == DL_DEX || kind == DL_CDEX || kind == DL_ELF;
}

void dl_path_join(const char *comps, int n, size_t stride, int truncated,
                  char *out, size_t cap)
{
    if (!out || cap == 0) return;
    size_t len = 0;
    out[0] = '\0';
    if (truncated) {
        len = (size_t)snprintf(out, cap, "...");
        if (len >= cap) { out[cap - 1] = '\0'; return; }
    }
    if (n <= 0) {
        if (!truncated) snprintf(out, cap, "/");
        return;
    }
    for (int i = n - 1; i >= 0; i--) {
        int w = snprintf(out + len, cap - len, "/%.*s", (int)stride, comps + (size_t)i * stride);
        if (w < 0 || (size_t)w >= cap - len) { out[cap - 1] = '\0'; return; }
        len += (size_t)w;
    }
}

int dl_maps_find_ino(const char *maps, unsigned long ino,
                     unsigned long *start, unsigned long *end)
{
    if (!maps || ino == 0) return 0;
    const char *p = maps;
    while (*p) {
        unsigned long s, e, off, in;
        char perms[8];
        unsigned maj, min;
        if (sscanf(p, "%lx-%lx %7s %lx %x:%x %lu", &s, &e, perms, &off, &maj, &min, &in) == 7
            && in == ino && off == 0) {
            if (start) *start = s;
            if (end)   *end = e;
            return 1;
        }
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

void dl_payload_name(char *out, size_t cap, const char *dir, unsigned pid,
                     unsigned long long ino, int kind)
{
    snprintf(out, cap, "%s/%u-%llu.%s", dir, pid, ino, dl_kind_ext(kind));
}

long long dl_copy_fd(int in_fd, const char *dst, char sha_hex[65])
{
    if (in_fd < 0 || !dst) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0) return -1;
    struct sha256_ctx c;
    sha256_init(&c);
    char buf[65536];
    long long total = 0;
    for (;;) {
        ssize_t r = read(in_fd, buf, sizeof buf);
        if (r == 0) break;
        if (r < 0) { close(out); return -1; }
        for (ssize_t w = 0; w < r; ) {
            ssize_t k = write(out, buf + w, (size_t)(r - w));
            if (k <= 0) { close(out); return -1; }
            w += k;
        }
        sha256_update(&c, buf, (size_t)r);
        total += r;
    }
    if (close(out) != 0) return -1;
    if (sha_hex) sha256_final_hex(&c, sha_hex);
    return total;
}
