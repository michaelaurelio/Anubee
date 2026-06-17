// SPDX-License-Identifier: GPL-2.0
//
// Shared device launch/UID helpers, used by every engine that spawns or attaches
// to an Android app. Exported via COMMON_API (kept global through the partial-link).
#ifndef __ARES_COMMON_LAUNCH_H
#define __ARES_COMMON_LAUNCH_H

#include <sys/types.h>
#include <stddef.h>

// Run `cmd` via /system/bin/sh -c. If `out` != NULL, capture up to outsz-1 bytes
// of stdout (NUL-terminated). Returns the child wait status, or -1 on spawn error.
int ares_sh_exec(const char *cmd, char *out, size_t outsz);

// Resolve an installed package's app-UID from its data dir. Returns uid, or -1.
int ares_resolve_uid(const char *pkg);

// Read the UID of a running pid from /proc/<pid>/status. Returns uid, or -1.
int ares_get_pid_uid(pid_t pid);

// Resolve a package's launchable component ("pkg/.Activity") via `cmd package
// resolve-activity --brief`. Writes into `out`; returns 0 on success, -1 otherwise.
int ares_resolve_component(const char *pkg, char *out, size_t outsz);

#endif /* __ARES_COMMON_LAUNCH_H */
