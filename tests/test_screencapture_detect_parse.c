// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the screencapture-detect dumpsys output parser. REAL_FIXTURE
// is genuine `dumpsys activity services` output captured 2026-07-13 from a
// connected test device (com.transsion.screenrecorder's exported
// RecordingService, triggered via `adb shell am start-foreground-service`) --
// not a synthetic guess. See design doc's Motivation/Scope for how this was
// confirmed.
#include <stdio.h>
#include <string.h>
#include "modules/screencapture_detect_parse.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static const char *REAL_FIXTURE =
"ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
"  User 0 active services:\n"
"  * ServiceRecord{9734fa9 u0 com.transsion.screenrecorder/.service.RecordingService c:com.android.shell}\n"
"    intent={act=transsion.intent.screenrecorder.RECORDER_SERVICE cmp=com.transsion.screenrecorder/.service.RecordingService}\n"
"    packageName=com.transsion.screenrecorder\n"
"    processName=com.transsion.screenrecorder\n"
"    targetSdkVersion=36\n"
"    baseDir=/system_ext/app/TranScreenRecord/TranScreenRecord.apk\n"
"    dataDir=/data/user/0/com.transsion.screenrecorder\n"
"    app=ProcessRecord{d056ccf 7570:com.transsion.screenrecorder/u0a153}\n"
"    isForeground=true foregroundId=4276 types=0x000000A0 foregroundNoti=Notification(channel=screen_record)\n"
"    createTime=-1s198ms startingBgTimeout=--\n";

int main(void)
{
    int pid;

    // ---- real fixture, matching package -> active, pid parsed -------------
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(REAL_FIXTURE, "com.transsion.screenrecorder", &pid) == 1,
          "real fixture: active session detected");
    CHECK(pid == 7570, "real fixture: pid parsed as 7570");

    // ---- real fixture, non-matching package -> inactive -------------------
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(REAL_FIXTURE, "com.other.app", &pid) == 0,
          "real fixture: wrong package -> not found");
    CHECK(pid == -1, "real fixture: wrong package -> pid stays -1");

    // ---- microphone-only mask (0x80, no 0x20 bit) -> inactive --------------
    static const char *MIC_ONLY =
        "  * ServiceRecord{abc u0 com.example.app/.Svc}\n"
        "    app=ProcessRecord{xyz 1234:com.example.app/u0a1}\n"
        "    isForeground=true types=0x00000080\n";
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(MIC_ONLY, "com.example.app", &pid) == 0,
          "microphone-only mask -> not found");

    // ---- combined mask including 0x20 -> active -----------------------------
    static const char *COMBINED =
        "  * ServiceRecord{abc u0 com.example.app/.Svc}\n"
        "    app=ProcessRecord{xyz 4321:com.example.app/u0a1}\n"
        "    isForeground=true types=0x00000021\n"; // MEDIA_PROJECTION|DATA_SYNC
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(COMBINED, "com.example.app", &pid) == 1,
          "combined mask with 0x20 bit -> found");
    CHECK(pid == 4321, "combined mask: pid parsed as 4321");

    // ---- isForeground=false -> inactive even with matching mask ------------
    static const char *NOT_FG =
        "  * ServiceRecord{abc u0 com.example.app/.Svc}\n"
        "    app=ProcessRecord{xyz 1234:com.example.app/u0a1}\n"
        "    isForeground=false types=0x00000020\n";
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(NOT_FG, "com.example.app", &pid) == 0,
          "isForeground=false -> not found");

    // ---- matching block but no ProcessRecord line -> active, pid stays -1 --
    static const char *NO_PROC =
        "  * ServiceRecord{abc u0 com.example.app/.Svc}\n"
        "    isForeground=true types=0x00000020\n";
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(NO_PROC, "com.example.app", &pid) == 1,
          "no ProcessRecord line -> still found active");
    CHECK(pid == -1, "no ProcessRecord line -> pid stays -1 (graceful degrade)");

    // ---- multiple blocks: first non-matching, second matching --------------
    static const char *TWO_BLOCKS =
        "  * ServiceRecord{aaa u0 com.other.app/.Svc}\n"
        "    app=ProcessRecord{aaa 111:com.other.app/u0a1}\n"
        "    isForeground=true types=0x00000020\n"
        "  * ServiceRecord{bbb u0 com.example.app/.Svc}\n"
        "    app=ProcessRecord{bbb 222:com.example.app/u0a2}\n"
        "    isForeground=true types=0x00000020\n";
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(TWO_BLOCKS, "com.example.app", &pid) == 1,
          "two blocks: second block matches");
    CHECK(pid == 222, "two blocks: pid from the matching (second) block");

    // ---- unusable input ------------------------------------------------------
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(NULL, "com.example.app", &pid) == -1, "NULL buf -> -1");
    CHECK(pid == -1, "NULL buf -> pid stays -1");
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys("", "com.example.app", &pid) == -1, "empty buf -> -1");
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(REAL_FIXTURE, NULL, &pid) == -1, "NULL pkg -> -1");
    pid = -1;
    CHECK(screencapture_detect_parse_dumpsys(REAL_FIXTURE, "", &pid) == -1, "empty pkg -> -1");

    // ---- out_pid may be NULL (caller doesn't care about the pid) -----------
    CHECK(screencapture_detect_parse_dumpsys(REAL_FIXTURE, "com.transsion.screenrecorder", NULL) == 1,
          "NULL out_pid is tolerated");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
