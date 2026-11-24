// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the execve analyzer's classifier: which categories a
// command falls in (root tooling, recon, tampering, device control, shell,
// run from an app-writable folder, run from memory), including the commands
// inside `sh -c "..."`.
#include <stdio.h>
#include <string.h>
#include "modules/execve_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

#define CLS(file, ...) ({ const char *av_[] = { __VA_ARGS__ }; \
    ex_classify(file, av_, (int)(sizeof av_ / sizeof av_[0])); })

int main(void)
{
    CHECK(CLS("/system/bin/su", "su", "-c", "id") & EXF_ROOT, "su is root tooling");
    CHECK(CLS("/data/adb/magisk/magisk", "magisk", "-v") & EXF_ROOT, "magisk is root tooling");
    CHECK(CLS("/system/bin/getprop", "getprop", "ro.build.tags") == EXF_RECON, "getprop is recon only");
    CHECK(CLS("/system/bin/pm", "pm", "list", "packages") == EXF_RECON, "pm list is recon");
    CHECK(CLS("/system/bin/pm", "pm", "install", "/sdcard/x.apk") == EXF_TAMPER, "pm install is tampering");
    CHECK(CLS("/system/bin/pm", "pm", "grant", "com.example.app", "android.permission.READ_SMS") == EXF_TAMPER,
          "pm grant is tampering");
    CHECK(CLS("/system/bin/settings", "settings", "get", "secure", "android_id") == EXF_RECON, "settings get is recon");
    CHECK(CLS("/system/bin/settings", "settings", "put", "secure", "enabled_accessibility_services", "x") == EXF_TAMPER,
          "settings put is tampering");
    CHECK(CLS("/system/bin/input", "input", "tap", "100", "200") == EXF_CONTROL, "input is device control");
    CHECK(CLS("/system/bin/screencap", "screencap", "-p") == EXF_CONTROL, "screencap is device control");
    CHECK(CLS("/system/bin/setenforce", "setenforce", "0") == EXF_TAMPER, "setenforce is tampering");
    CHECK(CLS("/system/bin/ls", "ls", "/data") == 0, "ls is nothing in particular");
    CHECK(CLS("/system/bin/linker64", "linker64") == 0, "linker is nothing in particular");

    // toybox / toolbox / busybox multi-call: the applet decides
    CHECK(CLS("/system/bin/toybox", "toybox", "getprop") == EXF_RECON, "toybox applet classified");
    CHECK((CLS("/data/local/tmp/busybox", "busybox", "id") & (EXF_ROOT | EXF_RECON | EXF_APP_DIR))
          == (EXF_ROOT | EXF_RECON | EXF_APP_DIR), "busybox: root tooling + applet + app dir");

    // shell -c: the commands inside count
    unsigned f = CLS("/system/bin/sh", "sh", "-c", "pm list packages; id && su -c setenforce 0");
    CHECK(f & EXF_SHELL, "sh is a shell");
    CHECK(f & EXF_RECON, "sh -c: pm list / id found");
    CHECK(f & EXF_ROOT, "sh -c: su found");
    CHECK(CLS("/system/bin/sh", "sh", "-c", "/data/user/0/com.example.app/files/x | getprop") & EXF_APP_DIR,
          "sh -c: binary in the app's folder");
    CHECK(CLS("/system/bin/sh", "sh", "-c", "echo hi") == EXF_SHELL, "sh -c echo is just a shell");

    // where the binary lives
    CHECK(CLS("/data/data/com.example.app/files/payload", "payload") == EXF_APP_DIR, "app data dir");
    CHECK(CLS("/data/user/0/com.example.app/cache/x", "x") == EXF_APP_DIR, "app user dir");
    CHECK(CLS("/data/local/tmp/x", "x") == EXF_APP_DIR, "/data/local/tmp");
    CHECK(CLS("/storage/emulated/0/Download/x", "x") == EXF_APP_DIR, "external storage");
    CHECK(CLS("./x", "x") == EXF_APP_DIR, "relative path (cwd is usually the app's folder)");
    CHECK(CLS("/system/bin/id", "id") == EXF_RECON, "system binary is not app dir");
    CHECK(CLS("/proc/self/fd/7", "x") == EXF_MEMFD, "fexecve of a memfd");
    CHECK(CLS("/dev/fd/3", "x") == EXF_MEMFD, "/dev/fd exec");

    // names
    char buf[128];
    ex_flag_names(EXF_ROOT | EXF_APP_DIR, buf, sizeof buf);
    CHECK(strcmp(buf, "root,app_dir") == 0, "flag names joined in bit order");
    ex_flag_names(0, buf, sizeof buf);
    CHECK(buf[0] == '\0', "no flags -> empty");
    CHECK(CLS("", "") == 0 && ex_classify(NULL, NULL, 0) == 0, "empty / NULL input");

    printf("test_execve_classify: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
