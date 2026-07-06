// SPDX-License-Identifier: GPL-2.0
// Pure classification logic for the `ares mod file-access` analyzer. No libbpf
// deps (host-testable): given an opened path and the traced app's own package
// name (or NULL if unknown), decide which malware-relevant categories it hits.
#ifndef __ARES_FILE_ACCESS_CLASSIFY_H
#define __ARES_FILE_ACCESS_CLASSIFY_H

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

#endif /* __ARES_FILE_ACCESS_CLASSIFY_H */
