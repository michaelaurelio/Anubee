// SPDX-License-Identifier: GPL-2.0
// Implementation of the dumpsys output parser declared in
// screencapture_detect_parse.h. See that header for the contract.
#include <string.h>
#include <stdlib.h>
#include "modules/screencapture_detect_parse.h"

// Bounded substring search: plain strstr() requires a NUL-terminated
// haystack, but ServiceRecord block boundaries here are found by pointer
// arithmetic partway through one large buffer, not by NUL bytes -- this
// scans exactly hay_len bytes and never reads past it.
static const char *find_in(const char *hay, size_t hay_len, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hay_len)
        return NULL;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

// Parses a "0x"-prefixed hex mask starting at p, stopping at the first
// non-hex-digit byte or at end (exclusive). No NUL-termination assumed at
// the mask's end -- real dumpsys output has more text right after it on the
// same line.
static unsigned long parse_hex_mask(const char *p, const char *end)
{
    if (p + 2 <= end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;
    unsigned long v = 0;
    while (p < end) {
        char c = *p;
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') digit = 10 + (c - 'A');
        else break;
        v = v * 16 + (unsigned long)digit;
        p++;
    }
    return v;
}

int screencapture_detect_parse_dumpsys(const char *buf, const char *pkg, int *out_pid)
{
    if (out_pid) *out_pid = -1;
    if (!buf || !buf[0] || !pkg || !pkg[0])
        return -1;

    size_t buf_len = strlen(buf);
    const char *buf_end = buf + buf_len;
    const char *block = find_in(buf, buf_len, "ServiceRecord{");

    while (block) {
        const char *next = find_in(block + 1, (size_t)(buf_end - (block + 1)), "ServiceRecord{");
        const char *block_end = next ? next : buf_end;
        size_t block_len = (size_t)(block_end - block);

        int has_pkg = find_in(block, block_len, pkg) != NULL;
        int has_fg  = find_in(block, block_len, "isForeground=true") != NULL;
        const char *types_p = find_in(block, block_len, "types=0x");

        if (has_pkg && has_fg && types_p) {
            const char *mask_start = types_p + strlen("types=");
            unsigned long mask = parse_hex_mask(mask_start, block_end);
            if (mask & SCREENCAPTURE_DETECT_FGS_TYPE_BIT) {
                if (out_pid) {
                    const char *pr = find_in(block, block_len, "ProcessRecord{");
                    if (pr) {
                        const char *p = pr + strlen("ProcessRecord{");
                        const char *sp = find_in(p, (size_t)(block_end - p), " ");
                        if (sp) {
                            int pid = atoi(sp + 1);
                            if (pid > 0) *out_pid = pid;
                        }
                    }
                }
                return 1;
            }
        }

        block = next;
    }
    return 0;
}

int sc_stage_of(const char *iface, const char *method)
{
    if (!iface || !method) return SC_NONE;
    if (!strcmp(iface, SC_IFACE_PROJECTION) && !strcmp(method, "start"))
        return SC_PROJECTION_START;
    if (!strcmp(iface, SC_IFACE_DISPLAY) && !strcmp(method, "createVirtualDisplay"))
        return SC_VIRTUAL_DISPLAY;
    return SC_NONE;
}

const char *sc_stage_name(int stage)
{
    static const char *const names[SC_STAGE_N] = {
        "none", "fgs_declared", "projection_start", "virtual_display",
    };
    return stage > SC_NONE && stage < SC_STAGE_N ? names[stage] : names[SC_NONE];
}

int sc_stage_alerts(int stage, unsigned seen)
{
    if (stage == SC_VIRTUAL_DISPLAY)
        return (seen & (1u << SC_PROJECTION_START | 1u << SC_FGS_DECLARED)) != 0;
    return stage > SC_NONE && stage < SC_STAGE_N;
}
