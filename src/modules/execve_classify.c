// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include "modules/execve_classify.h"

static const char *basename_of(const char *p)
{
    const char *b = strrchr(p, '/');
    return b ? b + 1 : p;
}

static int in_list(const char *s, const char *const *list)
{
    for (int i = 0; list[i]; i++)
        if (!strcmp(s, list[i])) return 1;
    return 0;
}

static const char *const root_bins[] = {
    "su", "magisk", "magiskpolicy", "magiskinit", "ksud", "apd", "busybox",
    "resetprop", "supolicy", "daemonsu", NULL,
};
static const char *const shell_bins[] = { "sh", "bash", "mksh", "ash", "dash", NULL };
static const char *const recon_bins[] = {
    "getprop", "dumpsys", "ps", "id", "uname", "whoami", "logcat", "ip", "ifconfig",
    "netstat", "ss", "which", "df", "lsof", "getenforce", NULL,
};
static const char *const tamper_bins[] = {
    "setenforce", "mount", "umount", "setprop", "iptables", "ip6tables", "chcon",
    "kill", "killall", "pkill", "reboot", "insmod", NULL,
};
static const char *const control_bins[] = {
    "am", "input", "cmd", "svc", "service", "screencap", "screenrecord", "monkey",
    "wm", "uiautomator", NULL,
};
// Subcommand-dependent tools: these subcommands change state, others read it.
static const char *const pm_tamper[] = {
    "install", "install-create", "uninstall", "grant", "revoke", "disable",
    "disable-user", "enable", "hide", "unhide", "suspend", "clear", "set-installer",
    "set-home-activity", NULL,
};
static const char *const settings_tamper[] = { "put", "delete", "reset", NULL };
static const char *const content_tamper[] = { "insert", "update", "delete", NULL };
static const char *const appops_tamper[] = { "set", "reset", NULL };

static unsigned where_flags(const char *path)
{
    static const char *const app_dirs[] = {
        "/data/data/", "/data/user/", "/data/user_de/", "/data/local/tmp/", "/data/media/",
        "/sdcard/", "/storage/", "/mnt/sdcard/", "/mnt/user/", NULL,
    };
    if (!strncmp(path, "/proc/", 6) && strstr(path, "/fd/")) return EXF_MEMFD;
    if (!strncmp(path, "/dev/fd/", 8)) return EXF_MEMFD;
    for (int i = 0; app_dirs[i]; i++)
        if (!strncmp(path, app_dirs[i], strlen(app_dirs[i]))) return EXF_APP_DIR;
    if (path[0] != '/' && strchr(path, '/')) return EXF_APP_DIR;   // ./x, files/x
    return 0;
}

// One command: tool name (basename) + its first argument (subcommand).
static unsigned tool_flags(const char *tool, const char *sub)
{
    unsigned f = 0;
    if (in_list(tool, root_bins))    f |= EXF_ROOT;
    if (in_list(tool, shell_bins))   f |= EXF_SHELL;
    if (in_list(tool, recon_bins))   f |= EXF_RECON;
    if (in_list(tool, tamper_bins))  f |= EXF_TAMPER;
    if (in_list(tool, control_bins)) f |= EXF_CONTROL;
    sub = sub ? sub : "";
    if (!strcmp(tool, "pm"))
        f |= in_list(sub, pm_tamper) ? EXF_TAMPER : EXF_RECON;
    else if (!strcmp(tool, "settings"))
        f |= in_list(sub, settings_tamper) ? EXF_TAMPER : EXF_RECON;
    else if (!strcmp(tool, "content"))
        f |= in_list(sub, content_tamper) ? EXF_TAMPER : EXF_RECON;
    else if (!strcmp(tool, "appops"))
        f |= in_list(sub, appops_tamper) ? EXF_TAMPER : EXF_CONTROL;
    return f;
}

// Multi-call binaries: the applet named by argv[1] is what runs.
static int is_multicall(const char *tool)
{
    return !strcmp(tool, "toybox") || !strcmp(tool, "toolbox") || !strcmp(tool, "busybox");
}

static unsigned argv_flags(const char *path, const char *const *argv, int argc)
{
    unsigned f = where_flags(path);
    const char *tool = basename_of(path);
    int a = 1;   // index of the first real argument
    if (is_multicall(tool)) {
        f |= tool_flags(tool, NULL);
        if (argc > 1 && argv[1]) { tool = basename_of(argv[1]); a = 2; }
    }
    f |= tool_flags(tool, argc > a ? argv[a] : NULL);
    return f;
}

// The commands of a `sh -c` string, split on ; & | and newlines; each
// segment's first two words are a tool and its subcommand.
static unsigned script_flags(const char *s)
{
    unsigned f = 0;
    char seg[256];
    while (*s) {
        size_t n = strcspn(s, ";&|\n");
        size_t m = n < sizeof seg - 1 ? n : sizeof seg - 1;
        memcpy(seg, s, m);
        seg[m] = '\0';
        char *words[3] = { 0 };
        int w = 0;
        for (char *t = strtok(seg, " \t"); t && w < 3; t = strtok(NULL, " \t"))
            words[w++] = t;
        // skip env assignments / redirections aren't worth parsing; "exec x" -> x
        int i = (w > 1 && !strcmp(words[0], "exec")) ? 1 : 0;
        if (words[i]) {
            const char *argv2[2] = { words[i], words[i + 1] };
            f |= argv_flags(words[i], argv2, words[i + 1] ? 2 : 1);
        }
        s += n;
        while (*s == ';' || *s == '&' || *s == '|' || *s == '\n') s++;
    }
    return f;
}

unsigned ex_classify(const char *filename, const char *const *argv, int argc)
{
    if (!filename || !filename[0]) return 0;
    unsigned f = argv_flags(filename, argv, argv ? argc : 0);
    if ((f & EXF_SHELL) && argv)
        for (int i = 1; i + 1 < argc; i++)
            if (argv[i] && !strcmp(argv[i], "-c") && argv[i + 1]) {
                f |= script_flags(argv[i + 1]);
                break;
            }
    // su -c "cmd": the command runs as root; classify it too.
    if ((f & EXF_ROOT) && argv)
        for (int i = 1; i + 1 < argc; i++)
            if (argv[i] && !strcmp(argv[i], "-c") && argv[i + 1]) {
                f |= script_flags(argv[i + 1]);
                break;
            }
    return f;
}

void ex_flag_names(unsigned flags, char *out, size_t cap)
{
    static const char *const names[] = { "root", "recon", "tamper", "control",
                                         "shell", "app_dir", "memfd" };
    if (!cap) return;
    out[0] = '\0';
    size_t len = 0;
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(flags & (1u << i))) continue;
        int w = snprintf(out + len, cap - len, "%s%s", len ? "," : "", names[i]);
        if (w < 0 || (size_t)w >= cap - len) { out[cap - 1] = '\0'; return; }
        len += (size_t)w;
    }
}
