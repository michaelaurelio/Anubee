// SPDX-License-Identifier: GPL-2.0
// Android package-name validation for anything that reaches a shell.
//
// In -p mode the package name comes from the target's /proc/<pid>/cmdline,
// which the traced process can rewrite at will; analyzers then interpolate it
// into root shell commands (dumpsys, appops). Accepting only a well-formed
// Java package name -- dot-separated segments, each [A-Za-z][A-Za-z0-9_]* --
// means no shell metacharacter, whitespace or leading '-' can get through.
#ifndef __ANUBEE_COMMON_PKG_NAME_H
#define __ANUBEE_COMMON_PKG_NAME_H

#define ANUBEE_PKG_NAME_MAX 255

static inline int anubee_pkg_name_ok(const char *s)
{
    if (!s || !*s)
        return 0;
    int len = 0, seg_start = 1;
    for (const char *p = s; *p; p++, len++) {
        char c = *p;
        if (len >= ANUBEE_PKG_NAME_MAX)
            return 0;
        if (c == '.') {
            if (seg_start) return 0;          // leading dot or empty segment
            seg_start = 1;
            continue;
        }
        int alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        int digit_us = (c >= '0' && c <= '9') || c == '_';
        if (seg_start ? !alpha : !(alpha || digit_us))
            return 0;
        seg_start = 0;
    }
    return !seg_start;                        // no trailing dot
}

#endif /* __ANUBEE_COMMON_PKG_NAME_H */
