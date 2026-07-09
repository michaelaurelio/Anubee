// SPDX-License-Identifier: GPL-2.0
//
// Single source of truth for the engine driver ABI that the `trace` coordinator
// (src/trace/trace.c) links against. Each engine's .c #includes this so its
// *definition* is compiler-checked against this *declaration* — that include is
// what makes a signature change a compile error instead of silent UB at the
// coordinator boundary (audit item AA3). The Makefile's --keep-global-symbol
// lists (*_DRIVER vars) must list exactly these symbols; tests/check_driver_symbols.sh
// diffs the two and fails the build on drift.
#ifndef __ARES_COMMON_ENGINE_DRIVER_H
#define __ARES_COMMON_ENGINE_DRIVER_H

#include <signal.h>   // sig_atomic_t

struct ares_run_ctx;  // fwd decl (defined in common/launch.h); params are pointers

#define ARES_ENGINE_DRIVER(e)                                              \
    int  e##_setup(int argc, char **argv, const struct ares_run_ctx *rc);  \
    int  e##_run(volatile sig_atomic_t *stop);                             \
    void e##_teardown(void)

ARES_ENGINE_DRIVER(syscalls);
ARES_ENGINE_DRIVER(funcs);
ARES_ENGINE_DRIVER(lib);
ARES_ENGINE_DRIVER(correlate);
ARES_ENGINE_DRIVER(dump);

#endif /* __ARES_COMMON_ENGINE_DRIVER_H */
