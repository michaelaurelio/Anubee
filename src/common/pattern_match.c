// SPDX-License-Identifier: GPL-2.0
#include "common/pattern_match.h"

#include <fnmatch.h>
#include <regex.h>
#include <string.h>

bool pm_is_glob(const char *pattern)
{
    return strpbrk(pattern, "*?[") != NULL;
}

bool pm_is_regex(const char *pattern)
{
    size_t n = strlen(pattern);
    return n >= 2 && pattern[0] == '/' && pattern[n - 1] == '/';
}

bool pm_match(const char *pattern, const char *text, bool exact)
{
    if (pm_is_glob(pattern))
        return fnmatch(pattern, text, 0) == 0;
    return exact ? strcmp(text, pattern) == 0 : strstr(text, pattern) != NULL;
}

bool pm_regex(const char *pattern, const char *text)
{
    char buf[256];
    const char *re_src = pattern;

    if (pm_is_regex(pattern)) {
        size_t inner = strlen(pattern) - 2;
        if (inner >= sizeof(buf))
            inner = sizeof(buf) - 1;
        memcpy(buf, pattern + 1, inner);
        buf[inner] = '\0';
        re_src = buf;
    }

    regex_t re;
    if (regcomp(&re, re_src, REG_EXTENDED | REG_NOSUB) != 0)
        return false;
    bool match = regexec(&re, text, 0, NULL, 0) == 0;
    regfree(&re);
    return match;
}

bool pm_regex_valid(const char *pattern, char *err, size_t errlen)
{
    char buf[256];
    const char *re_src = pattern;

    if (pm_is_regex(pattern)) {
        size_t inner = strlen(pattern) - 2;
        if (inner >= sizeof(buf))
            inner = sizeof(buf) - 1;
        memcpy(buf, pattern + 1, inner);
        buf[inner] = '\0';
        re_src = buf;
    }

    regex_t re;
    int rc = regcomp(&re, re_src, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        if (err && errlen)
            regerror(rc, &re, err, errlen);
        return false;
    }
    regfree(&re);
    return true;
}
