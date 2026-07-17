// SPDX-License-Identifier: GPL-2.0
//
// Shared device launch/UID helpers, used by every engine that spawns or attaches
// to an Android app. Exported via COMMON_API (kept global through the partial-link).
#ifndef __ANUBEE_COMMON_LAUNCH_H
#define __ANUBEE_COMMON_LAUNCH_H

#include <sys/types.h>
#include <stddef.h>

// Per-run context handed to an engine's *_setup() so it can be driven either
// standalone (cmd_<engine>) or by the `trace` coordinator. When `uid > 0` the
// engine arms that UID instead of resolving it from the package.
struct anubee_run_ctx {
	int uid;              // pre-resolved app UID to arm (<= 0 => resolve from pkg)
	const char *pkg;      // coordinator-supplied package name, or NULL
};

// Run `cmd` via /system/bin/sh -c. If `out` != NULL, capture up to outsz-1 bytes
// of stdout (NUL-terminated). Returns the child wait status, or -1 on spawn error.
int anubee_sh_exec(const char *cmd, char *out, size_t outsz);

// Resolve an installed package's app-UID from its data dir. Returns uid, or -1.
int anubee_resolve_uid(const char *pkg);

// Read the UID of a running pid from /proc/<pid>/status. Returns uid, or -1.
int anubee_get_pid_uid(pid_t pid);

// Best-effort resolve a running pid's package name from /proc/<pid>/cmdline
// (zygote sets cmdline to the package name for the common case; diverges for
// android:process-named secondary processes, e.g. ":remote" -- keeps only the
// part before ':' in that case). Returns 0 and fills buf, or -1 if unresolvable.
int anubee_resolve_pkg_from_pid(pid_t pid, char *buf, size_t bufsz);

// Resolve a package's launchable component ("pkg/.Activity") via `cmd package
// resolve-activity --brief`. Writes into `out`; returns 0 on success, -1 otherwise.
int anubee_resolve_component(const char *pkg, char *out, size_t outsz);

// Clean relaunch of an app: force-stop -> wait for the old process to die ->
// resolve the launchable component (or use `activity` verbatim if non-NULL) ->
// `am start -S -n <component>`. The caller must have already armed tracing
// (installed the UID filter / attached probes) so the fresh process is caught
// from its first instruction. Returns 0 on success, -1 otherwise.
// If `out_pid != NULL`, polls `pidof` after `am start` and writes the launched
// PID; returns -1 if the app started but no PID could be resolved within 3s.
int anubee_launch_app(const char *pkg, const char *activity, pid_t *out_pid);

// Uniform one-line launch banner ("launching <pkg> (uid N)") so every engine
// announces its single fresh relaunch the same way. Prints to stdout.
void anubee_launch_banner(const char *pkg, int uid);

#endif /* __ANUBEE_COMMON_LAUNCH_H */
