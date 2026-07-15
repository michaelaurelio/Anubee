// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the mod structured record builders. Pins the exact JSON
// for known events so the schema is stable for ares-mcp ingest.
#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "modules/mod_events.h"

void mod_emit_spawn(struct jbuf *j, const struct spawn_event *e);
void mod_emit_proc_exit(struct jbuf *j, const struct proc_exit_event *e);
void mod_emit_execve(struct jbuf *j, const struct execve_event *e, const char *const *syms);
void mod_emit_prop(struct jbuf *j, const struct prop_event *e);
#include "modules/file_access_classify.h"
void mod_emit_file_access(struct jbuf *j, const struct file_access_event *e,
                           unsigned categories, const char *const *flag_strs, int n_flags);
void mod_emit_massdelete_detect(struct jbuf *j, const struct massdelete_detect_event *e,
                                int distinct_estimate, int manage_ext_storage, int verbose);
void mod_emit_exfil_detect(struct jbuf *j, const struct exfil_detect_event *e,
                           const char *dest_str, int verbose);
void mod_emit_accessibility_detect(struct jbuf *j, const struct accessibility_detect_event *e, int granted);
void mod_emit_fileless_detect(struct jbuf *j, const struct fileless_detect_event *e);
void mod_emit_screencapture_detect(struct jbuf *j, const struct screencapture_detect_event *e);

static int checks = 0, failures = 0;
#define CHECK_HAS(j, sub, msg) do {                                  \
    checks++;                                                        \
    char tmp[4096]; int n = (int)(j).len; if (n > 4095) n = 4095;    \
    memcpy(tmp, (j).b, n); tmp[n] = 0;                               \
    if (!strstr(tmp, sub)) { failures++;                            \
        printf("  FAIL: %s\n    in: %s\n", msg, tmp); }              \
} while (0)

int main(void)
{
    struct jbuf j = {0};

    // ---- spawn event --------------------------------------------------------
    struct spawn_event se = {0};
    se.h.pid = 1000;
    se.h.tid = 1000;
    se.child_pid = 1500;
    se.ts_ns = 100000000001ULL;
    strncpy(se.comm, "zygote", TASK_COMM_LEN - 1);

    j.len = 0;
    mod_emit_spawn(&j, &se);
    CHECK_HAS(j, "\"type\":\"spawn\"",   "spawn type");
    CHECK_HAS(j, "\"pid\":1000",         "spawn pid");
    CHECK_HAS(j, "\"child_pid\":1500",   "spawn child_pid");
    CHECK_HAS(j, "\"ts_ns\":100000000001", "spawn ts_ns");
    CHECK_HAS(j, "\"comm\":\"zygote\"",  "spawn comm");

    // ---- proc_exit via exit status (exit_code = 42 << 8) --------------------
    struct proc_exit_event pe_status = {0};
    pe_status.h.pid = 2000;
    pe_status.h.tid = 2000;
    pe_status.ts_ns = 100000000002ULL;
    strncpy(pe_status.comm, "app", TASK_COMM_LEN - 1);
    pe_status.exit_code = 42 << 8;

    j.len = 0;
    mod_emit_proc_exit(&j, &pe_status);
    CHECK_HAS(j, "\"type\":\"proc_exit\"", "proc_exit type");
    CHECK_HAS(j, "\"pid\":2000",           "proc_exit pid");
    CHECK_HAS(j, "\"ts_ns\":100000000002", "proc_exit ts_ns");
    CHECK_HAS(j, "\"exit_status\":42",     "proc_exit exit_status");
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"signal\"")) { failures++; printf("  FAIL: signal emitted for clean exit\n    in: %s\n", tmp); }
    }

    // ---- proc_exit killed by signal 9 (exit_code = 9) -----------------------
    struct proc_exit_event pe_signal = {0};
    pe_signal.h.pid = 3000;
    pe_signal.h.tid = 3000;
    strncpy(pe_signal.comm, "victim", TASK_COMM_LEN - 1);
    pe_signal.exit_code = 9;

    j.len = 0;
    mod_emit_proc_exit(&j, &pe_signal);
    CHECK_HAS(j, "\"signal\":9", "proc_exit signal");
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"exit_status\"")) { failures++; printf("  FAIL: exit_status emitted for signal kill\n    in: %s\n", tmp); }
    }

    // ---- execve: 2 argv entries + 2-frame backtrace -------------------------
    struct execve_event ex = {0};
    ex.h.type      = MOD_EV_EXECVE;
    ex.h.pid       = 5000;
    ex.h.tid       = 5000;
    ex.argc        = 2;
    ex.stack_depth = 2;
    ex.ts_ns       = 100000000003ULL;
    strncpy(ex.comm,     "sh",      TASK_COMM_LEN - 1);
    strncpy(ex.filename, "/bin/sh", sizeof(ex.filename) - 1);
    strncpy(ex.argv[0],  "-c",      MAX_ARGV_STR - 1);
    strncpy(ex.argv[1],  "id",      MAX_ARGV_STR - 1);
    ex.call_stack[0] = 0xdeadbeef000ULL;
    ex.call_stack[1] = 0xcafebabe000ULL;

    // addr-only: syms=NULL → no "symbol" field
    j.len = 0;
    mod_emit_execve(&j, &ex, NULL);
    CHECK_HAS(j, "\"type\":\"execve\"",  "execve type");
    CHECK_HAS(j, "\"pid\":5000",          "execve pid");
    CHECK_HAS(j, "\"ts_ns\":100000000003", "execve ts_ns");
    CHECK_HAS(j, "\"/bin/sh\"",           "execve filename");
    CHECK_HAS(j, "\"argc\":2",            "execve argc");
    CHECK_HAS(j, "\"-c\"",               "execve argv[0]");
    CHECK_HAS(j, "\"id\"",               "execve argv[1]");
    CHECK_HAS(j, "\"addr\":\"",           "execve backtrace addr present");
    { char tmp[4096]; int n = (int)j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"symbol\"")) { failures++; printf("  FAIL: symbol emitted when syms=NULL\n    in: %s\n", tmp); }
    }

    // symbolized: syms != NULL → "symbol" field present per frame
    const char *syms2[2] = { "libc.so!fork+0x10", "app!main+0x40" };
    j.len = 0;
    mod_emit_execve(&j, &ex, syms2);
    CHECK_HAS(j, "\"symbol\":\"libc.so!fork+0x10\"", "execve symbol frame 0");
    CHECK_HAS(j, "\"symbol\":\"app!main+0x40\"",      "execve symbol frame 1");

    // ---- prop GET call (is_ret=0) --------------------------------------------
    struct prop_event pg = {0};
    pg.h.type  = MOD_EV_PROP_GET;
    pg.h.pid   = 6000;
    pg.h.tid   = 6000;
    pg.is_ret  = 0;
    pg.found   = 0;
    pg.ts_ns   = 100000000004ULL;
    strncpy(pg.comm,  "app",           TASK_COMM_LEN - 1);
    strncpy(pg.name,  "ro.debuggable", PROP_NAME_LEN - 1);

    j.len = 0;
    mod_emit_prop(&j, &pg);
    CHECK_HAS(j, "\"type\":\"prop\"",  "prop type");
    CHECK_HAS(j, "\"op\":\"get\"",     "prop op get");
    CHECK_HAS(j, "\"pid\":6000",       "prop pid");
    CHECK_HAS(j, "\"ts_ns\":100000000004", "prop ts_ns");
    CHECK_HAS(j, "\"ro.debuggable\"",  "prop name");
    CHECK_HAS(j, "\"is_ret\":0",       "prop is_ret 0");

    // ---- prop FIND return, not found (is_ret=1, found=0) --------------------
    struct prop_event pf = {0};
    pf.h.type  = MOD_EV_PROP_FIND;
    pf.h.pid   = 6000;
    pf.h.tid   = 6000;
    pf.is_ret  = 1;
    pf.found   = 0;
    strncpy(pf.comm,  "app",       TASK_COMM_LEN - 1);
    strncpy(pf.name,  "ro.secure", PROP_NAME_LEN - 1);

    j.len = 0;
    mod_emit_prop(&j, &pf);
    CHECK_HAS(j, "\"op\":\"find\"", "prop op find");
    CHECK_HAS(j, "\"is_ret\":1",    "prop is_ret 1");
    CHECK_HAS(j, "\"found\":0",     "prop found 0");

    // ---- prop SCAN: marker only — name/value/is_ret/found must be absent --------
    struct prop_event ps = {0};
    ps.h.type = MOD_EV_PROP_SCAN;
    ps.h.pid  = 7000;
    ps.h.tid  = 7000;
    strncpy(ps.comm, "app", TASK_COMM_LEN - 1);

    j.len = 0;
    mod_emit_prop(&j, &ps);
    CHECK_HAS(j, "\"op\":\"scan\"", "prop scan op");
    CHECK_HAS(j, "\"pid\":7000",    "prop scan pid");
    { char tmp[4096]; int n = (int)j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"name\""))   { failures++; printf("  FAIL: name emitted for SCAN\n    in: %s\n", tmp); }
      checks++;
      if (strstr(tmp, "\"value\""))  { failures++; printf("  FAIL: value emitted for SCAN\n    in: %s\n", tmp); }
      checks++;
      if (strstr(tmp, "\"is_ret\"")) { failures++; printf("  FAIL: is_ret emitted for SCAN\n    in: %s\n", tmp); }
      checks++;
      if (strstr(tmp, "\"found\""))  { failures++; printf("  FAIL: found emitted for SCAN\n    in: %s\n", tmp); }
    }

    // ---- file_access: external storage + media subdir ------------------------
    struct file_access_event fa = {0};
    fa.h.type = MOD_EV_FILE_ACCESS;
    fa.h.pid  = 8000;
    fa.h.tid  = 8000;
    fa.ts_ns  = 100000000005ULL;
    strncpy(fa.comm, "app", TASK_COMM_LEN - 1);
    strncpy(fa.path, "/storage/emulated/0/DCIM/Camera/img.jpg", sizeof(fa.path) - 1);
    fa.flags = 0; // O_RDONLY

    const char *flags1[1] = { "O_RDONLY" };
    j.len = 0;
    mod_emit_file_access(&j, &fa, FA_EXTERNAL_STORAGE | FA_MEDIA_SUBDIR, flags1, 1);
    CHECK_HAS(j, "\"type\":\"file_access\"",      "file_access type");
    CHECK_HAS(j, "\"pid\":8000",                  "file_access pid");
    CHECK_HAS(j, "\"ts_ns\":100000000005",        "file_access ts_ns");
    CHECK_HAS(j, "\"path\":\"/storage/emulated/0/DCIM/Camera/img.jpg\"", "file_access path");
    CHECK_HAS(j, "\"flags\":[\"O_RDONLY\"]",      "file_access flags array");
    CHECK_HAS(j, "\"external_storage\"",          "file_access external_storage category");
    CHECK_HAS(j, "\"media_subdir\"",               "file_access media_subdir category");

    // ---- file_access: foreign app dir + write flags ---------------------------
    struct file_access_event fa2 = {0};
    fa2.h.type = MOD_EV_FILE_ACCESS;
    fa2.h.pid  = 8001;
    fa2.h.tid  = 8001;
    strncpy(fa2.comm, "app", TASK_COMM_LEN - 1);
    strncpy(fa2.path, "/data/data/com.other.app/databases/x.db", sizeof(fa2.path) - 1);

    const char *flags2[2] = { "O_WRONLY", "O_CREAT" };
    j.len = 0;
    mod_emit_file_access(&j, &fa2, FA_FOREIGN_APP_DIR, flags2, 2);
    CHECK_HAS(j, "\"foreign_app_dir\"",           "file_access foreign_app_dir category");
    CHECK_HAS(j, "\"flags\":[\"O_WRONLY\",\"O_CREAT\"]", "file_access multi-flag array");

    // ---- file_access: no categories -> empty categories array ------------------
    struct file_access_event fa3 = {0};
    fa3.h.type = MOD_EV_FILE_ACCESS;
    fa3.h.pid  = 8002;
    strncpy(fa3.comm, "app", TASK_COMM_LEN - 1);
    strncpy(fa3.path, "/data/data/com.example.app/files/x", sizeof(fa3.path) - 1);

    j.len = 0;
    mod_emit_file_access(&j, &fa3, 0, flags1, 1);
    CHECK_HAS(j, "\"categories\":[]", "file_access empty categories array when uncategorized");

    // ---- massdelete_detect: full event, MANAGE_EXTERNAL_STORAGE granted ------
    struct massdelete_detect_event rb = {0};
    rb.h.type = MOD_EV_MASSDELETE_DETECT;
    rb.h.pid  = 9000;
    rb.h.tid  = 9000;
    rb.ts_ns  = 100000000006ULL;
    strncpy(rb.comm, "malware", TASK_COMM_LEN - 1);
    rb.touch_count = 3;
    rb.window_ms   = 3500;
    strncpy(rb.paths[0], "/sdcard/DCIM/photo1.jpg.locked", FILE_PATH_LEN - 1);
    strncpy(rb.paths[1], "/sdcard/DCIM/photo2.jpg.locked", FILE_PATH_LEN - 1);
    strncpy(rb.paths[2], "/sdcard/DCIM/photo3.jpg.locked", FILE_PATH_LEN - 1);
    strncpy(rb.sample_path, "/sdcard/DCIM/photo3.jpg.locked", sizeof(rb.sample_path) - 1);

    j.len = 0;
    mod_emit_massdelete_detect(&j, &rb, 3, 1, 0);
    CHECK_HAS(j, "\"type\":\"massdelete_detect\"",  "massdelete_detect type");
    CHECK_HAS(j, "\"pid\":9000",                   "massdelete_detect pid");
    CHECK_HAS(j, "\"ts_ns\":100000000006",         "massdelete_detect ts_ns");
    CHECK_HAS(j, "\"comm\":\"malware\"",           "massdelete_detect comm");
    CHECK_HAS(j, "\"touch_count\":3",              "massdelete_detect touch_count");
    CHECK_HAS(j, "\"distinct_estimate\":3",        "massdelete_detect distinct_estimate");
    CHECK_HAS(j, "\"window_ms\":3500",             "massdelete_detect window_ms");
    CHECK_HAS(j, "\"sample_path\":\"/sdcard/DCIM/photo3.jpg.locked\"", "massdelete_detect sample_path");
    CHECK_HAS(j, "\"manage_external_storage\":true", "massdelete_detect manage_external_storage true");
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"paths\":")) { failures++; printf("  FAIL: paths emitted when verbose=0\n    in: %s\n", tmp); }
    }

    // ---- massdelete_detect: MANAGE_EXTERNAL_STORAGE checked, not granted -----
    j.len = 0;
    mod_emit_massdelete_detect(&j, &rb, 3, 0, 0);
    CHECK_HAS(j, "\"manage_external_storage\":false", "massdelete_detect manage_external_storage false");

    // ---- massdelete_detect: MANAGE_EXTERNAL_STORAGE unknown (pkg unresolved) -
    j.len = 0;
    mod_emit_massdelete_detect(&j, &rb, 3, -1, 0);
    CHECK_HAS(j, "\"manage_external_storage\":null", "massdelete_detect manage_external_storage null");

    // ---- massdelete_detect: verbose=1 includes the full paths array -----------
    j.len = 0;
    mod_emit_massdelete_detect(&j, &rb, 3, 1, 1);
    CHECK_HAS(j, "\"paths\":[\"/sdcard/DCIM/photo1.jpg.locked\",\"/sdcard/DCIM/photo2.jpg.locked\",\"/sdcard/DCIM/photo3.jpg.locked\"]",
              "massdelete_detect verbose=1 -> full paths array");

    // ---- exfil_detect: full event, destination known -------------------------
    struct exfil_detect_event eb = {0};
    eb.h.type = MOD_EV_EXFIL_DETECT;
    eb.h.pid  = 9100;
    eb.h.tid  = 9100;
    eb.ts_ns  = 100000000007ULL;
    strncpy(eb.comm, "spyware", TASK_COMM_LEN - 1);
    eb.bytes_sent = 600000;
    eb.window_ms  = 4200;
    strncpy(eb.sample_path, "/sdcard/DCIM/photo1.jpg", sizeof(eb.sample_path) - 1);
    strncpy(eb.sensitive_paths[0], "/sdcard/DCIM/photo1.jpg", FILE_PATH_LEN - 1);
    strncpy(eb.sensitive_paths[1], "/sdcard/Download/creds.txt", FILE_PATH_LEN - 1);
    eb.sensitive_path_count = 2;
    eb.paths_truncated = 0;

    j.len = 0;
    mod_emit_exfil_detect(&j, &eb, "203.0.113.1:443", 0);
    CHECK_HAS(j, "\"type\":\"exfil_detect\"",       "exfil_detect type");
    CHECK_HAS(j, "\"pid\":9100",                   "exfil_detect pid");
    CHECK_HAS(j, "\"ts_ns\":100000000007",         "exfil_detect ts_ns");
    CHECK_HAS(j, "\"comm\":\"spyware\"",           "exfil_detect comm");
    CHECK_HAS(j, "\"bytes_sent\":600000",          "exfil_detect bytes_sent");
    CHECK_HAS(j, "\"window_ms\":4200",             "exfil_detect window_ms");
    CHECK_HAS(j, "\"sample_path\":\"/sdcard/DCIM/photo1.jpg\"", "exfil_detect sample_path");
    CHECK_HAS(j, "\"dest\":\"203.0.113.1:443\"",   "exfil_detect dest known");
    { char tmp[4096]; int n = j.len < 4095 ? (int)j.len : 4095; memcpy(tmp, j.b, n); tmp[n]=0;
      checks++;
      if (strstr(tmp, "\"sensitive_paths\":")) { failures++; printf("  FAIL: sensitive_paths emitted when verbose=0\n    in: %s\n", tmp); }
    }

    // ---- exfil_detect: no destination observed --------------------------------
    j.len = 0;
    mod_emit_exfil_detect(&j, &eb, NULL, 0);
    CHECK_HAS(j, "\"dest\":null", "exfil_detect dest null");

    // ---- exfil_detect: verbose=1 includes sensitive_paths, count, not truncated -
    j.len = 0;
    mod_emit_exfil_detect(&j, &eb, "203.0.113.1:443", 1);
    CHECK_HAS(j, "\"sensitive_paths\":[\"/sdcard/DCIM/photo1.jpg\",\"/sdcard/Download/creds.txt\"]",
              "exfil_detect verbose=1 -> sensitive_paths array");
    CHECK_HAS(j, "\"sensitive_path_count\":2", "exfil_detect verbose=1 -> sensitive_path_count");
    CHECK_HAS(j, "\"paths_truncated\":false",  "exfil_detect verbose=1 -> paths_truncated false");

    // ---- exfil_detect: verbose=1, ring wrapped (truncated) ---------------------
    eb.sensitive_path_count = 40;
    eb.paths_truncated = 1;
    j.len = 0;
    mod_emit_exfil_detect(&j, &eb, "203.0.113.1:443", 1);
    CHECK_HAS(j, "\"sensitive_path_count\":40", "exfil_detect truncated -> true count preserved");
    CHECK_HAS(j, "\"paths_truncated\":true",    "exfil_detect truncated -> paths_truncated true");

    // ---- accessibility_detect: full event, service granted -----------------------------
    struct accessibility_detect_event aa = {0};
    aa.h.type = MOD_EV_ACCESSIBILITY_DETECT;
    aa.h.pid  = 9200;
    aa.h.tid  = 9200;
    aa.ts_ns  = 100000000008ULL;
    strncpy(aa.comm, "fakebank", TASK_COMM_LEN - 1);
    aa.touch_count = 50;
    aa.window_ms   = 2100;

    j.len = 0;
    mod_emit_accessibility_detect(&j, &aa, 1);
    CHECK_HAS(j, "\"type\":\"accessibility_detect\"", "accessibility_detect type");
    CHECK_HAS(j, "\"pid\":9200",            "accessibility_detect pid");
    CHECK_HAS(j, "\"ts_ns\":100000000008",  "accessibility_detect ts_ns");
    CHECK_HAS(j, "\"comm\":\"fakebank\"",   "accessibility_detect comm");
    CHECK_HAS(j, "\"touch_count\":50",      "accessibility_detect touch_count");
    CHECK_HAS(j, "\"window_ms\":2100",      "accessibility_detect window_ms");
    CHECK_HAS(j, "\"granted\":true",        "accessibility_detect granted true");

    // ---- accessibility_detect: checked, not granted -------------------------------------
    j.len = 0;
    mod_emit_accessibility_detect(&j, &aa, 0);
    CHECK_HAS(j, "\"granted\":false", "accessibility_detect granted false");

    // ---- accessibility_detect: grant check unresolved (unknown) -------------------------
    j.len = 0;
    mod_emit_accessibility_detect(&j, &aa, -1);
    CHECK_HAS(j, "\"granted\":null", "accessibility_detect granted null");

    // ---- fileless_detect: untagged (no anon_name) -------------------------------
    struct fileless_detect_event fe = {0};
    fe.h.type = MOD_EV_FILELESS_DETECT;
    fe.h.pid  = 9300;
    fe.h.tid  = 9300;
    fe.ts_ns  = 100000000009ULL;
    strncpy(fe.comm, "droploader", TASK_COMM_LEN - 1);
    fe.start = 0x7f0000000000ULL;
    fe.size  = 4096;

    j.len = 0;
    mod_emit_fileless_detect(&j, &fe);
    CHECK_HAS(j, "\"type\":\"fileless_detect\"",     "fileless_detect type");
    CHECK_HAS(j, "\"pid\":9300",                    "fileless_detect pid");
    CHECK_HAS(j, "\"ts_ns\":100000000009",          "fileless_detect ts_ns");
    CHECK_HAS(j, "\"comm\":\"droploader\"",         "fileless_detect comm");
    CHECK_HAS(j, "\"start\":\"0x7f0000000000\"",    "fileless_detect start hex");
    CHECK_HAS(j, "\"size\":4096",                   "fileless_detect size");
    CHECK_HAS(j, "\"anon_name\":\"\"",              "fileless_detect anon_name empty");

    // ---- fileless_detect: tagged (non-dalvik anon_name present) -----------------
    // Exercises the serializer only -- nothing in the current runtime path
    // (pending_map + dalvik- suppression) ever actually populates a
    // non-empty anon_name; this just proves mod_emit_fileless_detect()
    // correctly serializes whatever value it's given.
    strncpy(fe.anon_name, "v8-jit", FILELESS_DETECT_TAG_LEN - 1);
    j.len = 0;
    mod_emit_fileless_detect(&j, &fe);
    CHECK_HAS(j, "\"anon_name\":\"v8-jit\"", "fileless_detect anon_name tagged");

    // ---- screencapture_detect: full event with Binder-call context -----------------
    struct screencapture_detect_event mp = {0};
    mp.h.type = MOD_EV_SCREENCAPTURE_DETECT;
    mp.h.pid  = 9400;
    mp.h.tid  = 9400;
    mp.ts_ns  = 100000000010ULL;
    strncpy(mp.comm, "fakebank", TASK_COMM_LEN - 1);
    mp.binder_calls_context = 7;

    j.len = 0;
    mod_emit_screencapture_detect(&j, &mp);
    CHECK_HAS(j, "\"type\":\"screencapture_detect\"",   "screencapture_detect type");
    CHECK_HAS(j, "\"pid\":9400",                    "screencapture_detect pid");
    CHECK_HAS(j, "\"ts_ns\":100000000010",          "screencapture_detect ts_ns");
    CHECK_HAS(j, "\"comm\":\"fakebank\"",           "screencapture_detect comm");
    CHECK_HAS(j, "\"binder_calls_context\":7",      "screencapture_detect binder_calls_context");

    // ---- screencapture_detect: zero Binder-call context (pid unresolved case) ------
    mp.binder_calls_context = 0;
    j.len = 0;
    mod_emit_screencapture_detect(&j, &mp);
    CHECK_HAS(j, "\"binder_calls_context\":0", "screencapture_detect binder_calls_context zero");

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
