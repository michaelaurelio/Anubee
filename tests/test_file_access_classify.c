// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the pure file-access path classifier.
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "modules/file_access_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- external storage, generic path (no known subdir) -------------------
    unsigned c = classify_path("/storage/emulated/0/backup.bin", "com.example.app");
    CHECK(c & FA_EXTERNAL_STORAGE, "external storage prefix matched");
    CHECK(!(c & FA_MEDIA_SUBDIR), "no known subdir -> no media subtag");

    // ---- external storage, known media subdir --------------------------------
    c = classify_path("/storage/emulated/0/DCIM/Camera/img.jpg", "com.example.app");
    CHECK(c & FA_EXTERNAL_STORAGE, "DCIM path still external storage");
    CHECK(c & FA_MEDIA_SUBDIR,     "DCIM recognized as known media subdir");

    // ---- /sdcard alias --------------------------------------------------------
    c = classify_path("/sdcard/Download/report.pdf", "com.example.app");
    CHECK(c & FA_EXTERNAL_STORAGE, "/sdcard alias matched");
    CHECK(c & FA_MEDIA_SUBDIR,     "Download recognized as known media subdir");

    // ---- credential-shaped filename anywhere ----------------------------------
    c = classify_path("/data/data/com.example.app/files/id_rsa", "com.example.app");
    CHECK(c & FA_CREDENTIAL_PATTERN, "id_rsa filename flagged as credential pattern");

    // ---- own package's data dir: no foreign/unknown flag ----------------------
    c = classify_path("/data/data/com.example.app/databases/app.db", "com.example.app");
    CHECK(!(c & FA_FOREIGN_APP_DIR), "own /data/data path is not foreign");
    CHECK(!(c & FA_UNKNOWN_SELF),    "self_pkg known -> no unknown-self tag");

    // ---- another app's /data/data: foreign -------------------------------------
    c = classify_path("/data/data/com.other.app/shared_prefs/x.xml", "com.example.app");
    CHECK(c & FA_FOREIGN_APP_DIR, "different package under /data/data flagged foreign");

    // ---- /data/user/<n>/<pkg> form, own package ---------------------------------
    c = classify_path("/data/user/0/com.example.app/cache/tmp", "com.example.app");
    CHECK(!(c & FA_FOREIGN_APP_DIR), "own /data/user/0/<pkg> path is not foreign");

    // ---- /data/user/<n>/<pkg> form, foreign package -----------------------------
    c = classify_path("/data/user/0/com.other.app/cache/tmp", "com.example.app");
    CHECK(c & FA_FOREIGN_APP_DIR, "different package under /data/user/0 flagged foreign");

    // ---- self_pkg unknown (PID-attach, unresolved) ------------------------------
    c = classify_path("/data/data/com.other.app/databases/x.db", NULL);
    CHECK(c & FA_UNKNOWN_SELF,     "self_pkg NULL -> unknown-self tag set");
    CHECK(!(c & FA_FOREIGN_APP_DIR), "self_pkg NULL -> foreign not asserted (can't tell)");

    // ---- path outside all four gated prefixes: no data-dir tag either way ------
    c = classify_path("/system/lib64/libc.so", "com.example.app");
    CHECK(!(c & (FA_EXTERNAL_STORAGE | FA_FOREIGN_APP_DIR | FA_UNKNOWN_SELF)),
          "unrelated system path gets no category");

    // ---- NULL path is handled without crashing ---------------------------------
    c = classify_path(NULL, "com.example.app");
    CHECK(c == 0, "NULL path classifies as no categories");

    // ---- anchoring: substring inside a different component must not match -----
    c = classify_path("/storage/emulated/0/MyDownloader/app.apk", "com.example.app");
    CHECK(!(c & FA_MEDIA_SUBDIR),
          "MyDownloader dir does not falsely match Download subdir substring");

    c = classify_path("/data/data/com.example.app/reseeded/data.db", "com.example.app");
    CHECK(!(c & FA_CREDENTIAL_PATTERN),
          "reseeded dir component does not falsely match seed credential pattern");

    // ---- anchoring: real component/basename matches must still fire -----------
    c = classify_path("/storage/emulated/0/DCIM", "com.example.app");
    CHECK(c & FA_MEDIA_SUBDIR, "path ending exactly at DCIM (no trailing slash) still matches");

    c = classify_path("/storage/emulated/0/wallet.dat", "com.example.app");
    CHECK(c & FA_CREDENTIAL_PATTERN, "basename wallet.dat still matches credential pattern");

    // ---- flag decoding ----------------------------------------------------------
    const char *out[8];
    int n = file_access_decode_flags(O_RDONLY, out, 8);
    CHECK(n == 1 && strcmp(out[0], "O_RDONLY") == 0, "O_RDONLY decodes alone");

    n = file_access_decode_flags(O_WRONLY | O_CREAT | O_TRUNC, out, 8);
    CHECK(n == 3, "write+create+trunc decodes to 3 flags");
    CHECK(strcmp(out[0], "O_WRONLY") == 0, "access-mode flag decoded first");
    CHECK(strcmp(out[1], "O_CREAT") == 0,  "O_CREAT decoded");
    CHECK(strcmp(out[2], "O_TRUNC") == 0,  "O_TRUNC decoded");

    n = file_access_decode_flags(O_RDWR | O_APPEND, out, 8);
    CHECK(n == 2, "RDWR+APPEND decodes to 2 flags");
    CHECK(strcmp(out[0], "O_RDWR") == 0,   "O_RDWR decoded");
    CHECK(strcmp(out[1], "O_APPEND") == 0, "O_APPEND decoded");

    // ---- own folder is tagged so it can be hidden ----------------------------
    c = classify_path("/data/data/com.example.app/databases/app.db", "com.example.app");
    CHECK(c == FA_OWN_APP_DIR, "own /data/data path tagged own_app_dir only");
    c = classify_path("/data/user/10/com.example.app/files", "com.example.app");
    CHECK(c == FA_OWN_APP_DIR, "own /data/user/<n> path tagged own_app_dir");
    c = classify_path("/data/data/com.example.app/files/id_rsa", "com.example.app");
    CHECK((c & FA_OWN_APP_DIR) && (c & FA_CREDENTIAL_PATTERN), "credential in own dir keeps both tags");
    CHECK(!(classify_path("/data/data/com.other.app/x", "com.example.app") & FA_OWN_APP_DIR),
          "foreign dir is not own");

    // ---- /proc probes (pid 4242 is the opener) -----------------------------------
    CHECK(fa_classify_proc(0, "/proc/self/maps", 4242, NULL) == FA_PROC_SELF, "self maps: hook/Frida scan");
    CHECK(fa_classify_proc(0, "/proc/self/status", 4242, NULL) == FA_PROC_SELF, "self status: TracerPid");
    CHECK(fa_classify_proc(0, "/proc/4242/task/4250/comm", 4242, NULL) == FA_PROC_SELF,
          "own pid, thread names (gum-js-loop)");
    CHECK(fa_classify_proc(0, "/proc/thread-self/status", 4242, NULL) == FA_PROC_SELF, "thread-self");
    CHECK(fa_classify_proc(0, "/proc/self/fd", 4242, NULL) == FA_PROC_SELF, "fd dir listing");
    CHECK(fa_classify_proc(0, "/proc/self/stat", 4242, NULL) == 0, "self stat: ordinary");
    CHECK(fa_classify_proc(0, "/proc/self/cmdline", 4242, NULL) == 0, "self cmdline: ordinary");
    CHECK(fa_classify_proc(0, "/proc/1/cmdline", 4242, NULL) == FA_PROC_OTHER, "another process: process scan");
    CHECK(fa_classify_proc(0, "/proc/999/status", 4242, NULL) == FA_PROC_OTHER, "another process status");
    CHECK(fa_classify_proc(0, "/proc/net/tcp", 4242, NULL) == FA_PROC_SYSTEM, "net/tcp: Frida port scan");
    CHECK(fa_classify_proc(0, "/proc/self/net/unix", 4242, NULL) == FA_PROC_SYSTEM, "self/net is the netns view");
    CHECK(fa_classify_proc(0, "/proc/cpuinfo", 4242, NULL) == FA_PROC_SYSTEM, "cpuinfo: emulator check");
    CHECK(fa_classify_proc(0, "/proc/tty/drivers", 4242, NULL) == FA_PROC_SYSTEM, "tty drivers: goldfish");
    CHECK(fa_classify_proc(0, "/proc/mounts", 4242, NULL) == FA_PROC_SYSTEM, "mounts: magisk");
    CHECK(fa_classify_proc(0, "/proc/meminfo", 4242, NULL) == 0, "meminfo: ordinary");
    CHECK(fa_classify_proc(0, "/proc/4242/task/4250/stat", 4242, NULL) == 0,
          "per-thread CPU stats: ordinary (profilers read these)");
    CHECK(fa_classify_proc(0, "/proc/self/task/4250/status", 4242, NULL) == FA_PROC_SELF,
          "per-thread status: TracerPid");
    CHECK(fa_classify_proc(1, "/proc/self/task/4250/comm", 4242, NULL) == 0,
          "writing a thread's comm is naming it, not probing");
    CHECK(fa_classify_proc(0, "/proc/self/pagemap", 4242, NULL) == 0, "pagemap: memory accounting");

    char norm[256];
    fa_proc_normalize("/proc/4242/task/4250/comm", 4242, norm, sizeof norm);
    CHECK(strcmp(norm, "/proc/self/task/*/comm") == 0, "own pid + thread id collapsed");
    fa_proc_normalize("/proc/self/task/77/status", 4242, norm, sizeof norm);
    CHECK(strcmp(norm, "/proc/self/task/*/status") == 0, "self thread id collapsed");
    fa_proc_normalize("/proc/1/cmdline", 4242, norm, sizeof norm);
    CHECK(strcmp(norm, "/proc/1/cmdline") == 0, "another process kept as is");
    fa_proc_normalize("/data/x", 4242, norm, sizeof norm);
    CHECK(strcmp(norm, "/data/x") == 0, "non-/proc untouched");
    CHECK(fa_classify_proc(0, "/data/x", 4242, NULL) == 0 && fa_classify_proc(0, NULL, 1, NULL) == 0,
          "non-/proc and NULL");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
