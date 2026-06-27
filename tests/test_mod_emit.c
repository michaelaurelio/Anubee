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

    free(j.b);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
