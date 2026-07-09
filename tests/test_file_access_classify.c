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

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
