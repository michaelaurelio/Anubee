// SPDX-License-Identifier: GPL-2.0
//
// Single source of truth for the engine driver ABI that the `trace` coordinator
// (src/trace/trace.c) links against. Each engine's .c #includes this so its
// *definition* is compiler-checked against this *declaration* — that include is
// what makes a signature change a compile error instead of silent UB at the
// coordinator boundary (audit item AA3). The Makefile's --keep-global-symbol
// lists (*_DRIVER vars) must list exactly these symbols; tests/check_driver_symbols.sh
// diffs the two and fails the build on drift.
#ifndef __ANUBEE_COMMON_ENGINE_DRIVER_H
#define __ANUBEE_COMMON_ENGINE_DRIVER_H

#include <signal.h>     // sig_atomic_t
#include <sys/types.h>  // pid_t

struct anubee_run_ctx;  // fwd decl (defined in common/launch.h); params are pointers

#define ANUBEE_ENGINE_DRIVER(e)                                              \
    int  e##_setup(int argc, char **argv, const struct anubee_run_ctx *rc);  \
    int  e##_run(volatile sig_atomic_t *stop);                             \
    void e##_teardown(void)

ANUBEE_ENGINE_DRIVER(syscalls);
ANUBEE_ENGINE_DRIVER(funcs);
ANUBEE_ENGINE_DRIVER(lib);
ANUBEE_ENGINE_DRIVER(correlate);
ANUBEE_ENGINE_DRIVER(dump);

// correlate's post-launch uprobe attach (GA2): -P mode can't attach uprobes
// until the launched child's PID is known, so the caller (standalone
// cmd_correlate, or trace's coordinator) calls this right after its single
// anubee_launch_app succeeds. No-op in -p attach mode. See correlate.c.
int correlate_attach(pid_t pid);

#endif /* __ANUBEE_COMMON_ENGINE_DRIVER_H */
