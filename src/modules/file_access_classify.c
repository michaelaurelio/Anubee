// SPDX-License-Identifier: GPL-2.0
#include "modules/file_access_classify.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int extract_component(const char *s, char *out, size_t outsz)
{
    const char *slash = strchr(s, '/');
    size_t len = slash ? (size_t)(slash - s) : strlen(s);
    if (len == 0 || len >= outsz)
        return -1;
    memcpy(out, s, len);
    out[len] = '\0';
    return 0;
}

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int path_has_component(const char *path, const char *comp)
{
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "/%s/", comp);
    if (n > 0 && (size_t)n < sizeof(needle) && strstr(path, needle))
        return 1;
    size_t plen = strlen(path), clen = strlen(comp);
    if (plen > clen + 1 &&
        path[plen - clen - 1] == '/' &&
        strcmp(path + plen - clen, comp) == 0)
        return 1;
    return 0;
}

unsigned classify_path(const char *path, const char *self_pkg)
{
    if (!path)
        return 0;

    unsigned cat = 0;

    if (strncmp(path, "/storage/emulated/", 18) == 0 ||
        strncmp(path, "/sdcard/", 8) == 0) {
        cat |= FA_EXTERNAL_STORAGE;
        static const char *const subdirs[] = {
            "DCIM", "Download", "Documents", "WhatsApp", "Telegram", "Pictures", NULL,
        };
        for (int i = 0; subdirs[i]; i++) {
            if (path_has_component(path, subdirs[i])) {
                cat |= FA_MEDIA_SUBDIR;
                break;
            }
        }
    }

    static const char *const cred_patterns[] = {
        ".keystore", "wallet", "id_rsa", ".pem", "cookies", "seed", NULL,
    };
    const char *base = basename_of(path);
    for (int i = 0; cred_patterns[i]; i++) {
        if (strstr(base, cred_patterns[i])) {
            cat |= FA_CREDENTIAL_PATTERN;
            break;
        }
    }

    const char *rest = NULL;
    if (strncmp(path, "/data/data/", 11) == 0) {
        rest = path + 11;
    } else if (strncmp(path, "/data/user/", 11) == 0) {
        const char *after_user = path + 11;
        const char *slash = strchr(after_user, '/');
        if (slash)
            rest = slash + 1;
    }
    if (rest) {
        char pkgseg[256];
        if (extract_component(rest, pkgseg, sizeof(pkgseg)) == 0) {
            if (!self_pkg)
                cat |= FA_UNKNOWN_SELF;
            else if (strcmp(pkgseg, self_pkg) != 0)
                cat |= FA_FOREIGN_APP_DIR;
            else
                cat |= FA_OWN_APP_DIR;
        }
    }

    return cat;
}

int file_access_decode_flags(unsigned flags, const char *out[], int max)
{
    int n = 0;
    unsigned acc = flags & O_ACCMODE;
    if (n < max) {
        out[n++] = (acc == O_WRONLY) ? "O_WRONLY"
                 : (acc == O_RDWR)   ? "O_RDWR"
                                     : "O_RDONLY";
    }
    if ((flags & O_CREAT)  && n < max) out[n++] = "O_CREAT";
    if ((flags & O_TRUNC)  && n < max) out[n++] = "O_TRUNC";
    if ((flags & O_APPEND) && n < max) out[n++] = "O_APPEND";
    return n;
}

// First path component after the /proc/<x>/ prefix matches one of list
// (exact component, or component followed by '/').
static int first_comp_in(const char *rest, const char *const *list)
{
    for (int i = 0; list[i]; i++) {
        size_t n = strlen(list[i]);
        if (!strncmp(rest, list[i], n) && (rest[n] == '\0' || rest[n] == '/'))
            return 1;
    }
    return 0;
}

// Under task/<tid>/: only what anti-analysis code reads (status for
// TracerPid, comm for Frida's thread names), and comm only when read.
static int task_sensitive(int writing, const char *rest)
{
    const char *s = strchr(rest + 5, '/');          // after "task/<tid>"
    if (!s) return 1;                               // listing the threads
    s++;
    if (!strcmp(s, "status")) return 1;
    if (!strcmp(s, "comm")) return !writing;
    return 0;
}

unsigned fa_classify_proc(int writing, const char *path, unsigned pid,
                          int (*own_tid)(unsigned pid, unsigned n))
{
    static const char *const self_sensitive[] = {
        "maps", "smaps", "status", "fd", "fdinfo", "mounts", "mountinfo",
        "mem", "environ", "wchan", "exe", NULL,
    };
    static const char *const system_wide[] = {
        "net", "cpuinfo", "version", "tty", "modules", "kallsyms", "mounts", "misc",
        "filesystems", "partitions", NULL,
    };
    if (!path || strncmp(path, "/proc/", 6)) return 0;
    const char *p = path + 6;
    const char *rest = NULL;
    int self = 0;
    if (!strncmp(p, "self/", 5) || !strcmp(p, "self")) {
        self = 1; rest = p[4] ? p + 5 : "";
    } else if (!strncmp(p, "thread-self/", 12)) {
        self = 1; rest = p + 12;
    } else if (*p >= '0' && *p <= '9') {
        char *end;
        unsigned long n = strtoul(p, &end, 10);
        if (*end != '/' && *end != '\0') return 0;
        rest = *end ? end + 1 : "";
        self = (n == pid) || (own_tid && own_tid(pid, (unsigned)n));
        if (!self) return FA_PROC_OTHER;
    }
    if (self) {
        if (!strncmp(rest, "net/", 4) || !strcmp(rest, "net")) return FA_PROC_SYSTEM;
        if (!strncmp(rest, "task/", 5)) return task_sensitive(writing, rest) ? FA_PROC_SELF : 0;
        if (!strcmp(rest, "task")) return FA_PROC_SELF;
        return first_comp_in(rest, self_sensitive) ? FA_PROC_SELF : 0;
    }
    return first_comp_in(p, system_wide) ? FA_PROC_SYSTEM : 0;
}

void fa_proc_normalize(const char *path, unsigned pid, char *out, size_t cap)
{
    if (!cap) return;
    if (!path || strncmp(path, "/proc/", 6)) { snprintf(out, cap, "%s", path ? path : ""); return; }
    const char *p = path + 6;
    char head[32];
    if (!strncmp(p, "self/", 5)) {
        p += 5;
        snprintf(head, sizeof head, "self");
    } else {
        char *end;
        unsigned long n = strtoul(p, &end, 10);
        if (end == p || *end != '/' || n != pid) { snprintf(out, cap, "%s", path); return; }
        p = end + 1;
        snprintf(head, sizeof head, "self");
    }
    if (!strncmp(p, "task/", 5)) {
        const char *t = p + 5;
        while (*t >= '0' && *t <= '9') t++;
        if (t > p + 5) { snprintf(out, cap, "/proc/%s/task/*%s", head, t); return; }
    }
    snprintf(out, cap, "/proc/%s/%s", head, p);
}
