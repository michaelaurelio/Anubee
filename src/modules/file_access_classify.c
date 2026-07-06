// SPDX-License-Identifier: GPL-2.0
#include "modules/file_access_classify.h"

#include <fcntl.h>
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
            if (strstr(path, subdirs[i])) {
                cat |= FA_MEDIA_SUBDIR;
                break;
            }
        }
    }

    static const char *const cred_patterns[] = {
        ".keystore", "wallet", "id_rsa", ".pem", "cookies", "seed", NULL,
    };
    for (int i = 0; cred_patterns[i]; i++) {
        if (strstr(path, cred_patterns[i])) {
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
