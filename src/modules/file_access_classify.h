// SPDX-License-Identifier: GPL-2.0
// Pure classification logic for the `anubee mod file-access` analyzer. No libbpf
// deps (host-testable): given an opened path and the traced app's own package
// name (or NULL if unknown), decide which malware-relevant categories it hits.
#ifndef __ANUBEE_FILE_ACCESS_CLASSIFY_H
#define __ANUBEE_FILE_ACCESS_CLASSIFY_H

#include <stddef.h>

// path is under /storage/emulated/... or /sdcard/...
#define FA_EXTERNAL_STORAGE   (1u << 0)
// set alongside FA_EXTERNAL_STORAGE when the path also matches a known
// interesting subdir (DCIM/Download/Documents/WhatsApp/Telegram/Pictures)
#define FA_MEDIA_SUBDIR       (1u << 1)
// basename/path matches a curated credential/keystore-shaped pattern
#define FA_CREDENTIAL_PATTERN (1u << 2)
// path is under another app's /data/data or /data/user/<n> dir (self_pkg known
// and differs from the path's package segment)
#define FA_FOREIGN_APP_DIR    (1u << 3)
// path is under a per-app data dir but self_pkg is NULL, so self-vs-foreign
// could not be determined
#define FA_UNKNOWN_SELF       (1u << 4)
// path is under the traced app's own /data/data or /data/user/<n> dir
// (self_pkg known) -- the bulk of opens; hidden from the console by default
#define FA_OWN_APP_DIR        (1u << 5)
// /proc probes (fa_classify_proc): the process inspecting itself the way
// anti-analysis code does (maps/smaps for Frida/Xposed, status for
// TracerPid, task/*/comm for Frida thread names, fd, mounts, mem, environ)
#define FA_PROC_SELF          (1u << 6)
// another process's /proc/<pid>/ entry: process scanning
#define FA_PROC_OTHER         (1u << 7)
// system-wide /proc state used for environment checks: net/ (Frida's
// port), cpuinfo / tty/drivers / version (emulator), mounts, modules
#define FA_PROC_SYSTEM        (1u << 8)

// Classify an opened path into a bitmask of the FA_* categories above.
// self_pkg is the launched/resolved package name, or NULL if unknown (e.g.
// -p PID-attach mode when the package couldn't be resolved). Never crashes on
// a NULL path (returns 0).
unsigned classify_path(const char *path, const char *self_pkg);

// Decode raw open()/openat() flags into an array of up to `max` static
// flag-name strings (access-mode flag first, then O_CREAT/O_TRUNC/O_APPEND if
// set). Returns the count written (>= 1 when max >= 1, since the access-mode
// flag is always emitted; 0 if max <= 0).
int file_access_decode_flags(unsigned flags, const char *out[], int max);

// Classify a /proc open by the process `pid` (its tgid). writing: opened
// for writing (a thread naming itself writes task/<tid>/comm). own_tid(pid,
// n), if given, says whether n is a thread of pid (/proc/<tid>/ is the
// process itself too); NULL = only pid itself counts. 0 for ordinary /proc
// reads (stat, cmdline, meminfo, per-thread stat ...) and anything outside
// /proc.
unsigned fa_classify_proc(int writing, const char *path, unsigned pid,
                          int (*own_tid)(unsigned pid, unsigned n));

// Summary key for a /proc path: the process's own pid becomes "self" and
// thread ids under task/ become "*", so per-thread probes collapse into one
// row. Other paths are copied unchanged.
void fa_proc_normalize(const char *path, unsigned pid, char *out, size_t cap);

#endif /* __ANUBEE_FILE_ACCESS_CLASSIFY_H */
