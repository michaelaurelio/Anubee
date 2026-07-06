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
    strncpy(se.comm, "zygote", TASK_COMM_LEN - 1);

    j.len = 0;
    mod_emit_spawn(&j, &se);
    CHECK_HAS(j, "\"type\":\"spawn\"",   "spawn type");
    CHECK_HAS(j, "\"pid\":1000",         "spawn pid");
    CHECK_HAS(j, "\"child_pid\":1500",   "spawn child_pid");
    CHECK_HAS(j, "\"comm\":\"zygote\"",  "spawn comm");

    // ---- proc_exit via exit status (exit_code = 42 << 8) --------------------
    struct proc_exit_event pe_status = {0};
    pe_status.h.pid = 2000;
    pe_status.h.tid = 2000;
    strncpy(pe_status.comm, "app", TASK_COMM_LEN - 1);
    pe_status.exit_code = 42 << 8;

    j.len = 0;
    mod_emit_proc_exit(&j, &pe_status);
    CHECK_HAS(j, "\"type\":\"proc_exit\"", "proc_exit type");
    CHECK_HAS(j, "\"pid\":2000",           "proc_exit pid");
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
    strncpy(pg.comm,  "app",           TASK_COMM_LEN - 1);
    strncpy(pg.name,  "ro.debuggable", PROP_NAME_LEN - 1);

    j.len = 0;
    mod_emit_prop(&j, &pg);
    CHECK_HAS(j, "\"type\":\"prop\"",  "prop type");
    CHECK_HAS(j, "\"op\":\"get\"",     "prop op get");
    CHECK_HAS(j, "\"pid\":6000",       "prop pid");
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
    strncpy(fa.comm, "app", TASK_COMM_LEN - 1);
    strncpy(fa.path, "/storage/emulated/0/DCIM/Camera/img.jpg", sizeof(fa.path) - 1);
    fa.flags = 0; // O_RDONLY

    const char *flags1[1] = { "O_RDONLY" };
    j.len = 0;
    mod_emit_file_access(&j, &fa, FA_EXTERNAL_STORAGE | FA_MEDIA_SUBDIR, flags1, 1);
    CHECK_HAS(j, "\"type\":\"file_access\"",      "file_access type");
    CHECK_HAS(j, "\"pid\":8000",                  "file_access pid");
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

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
