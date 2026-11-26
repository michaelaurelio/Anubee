// SPDX-License-Identifier: GPL-2.0
// Public accessors for the ZIP-central-directory reader in sym_apk.c. Everything
// else in that file is localized at the common.part.o link step (Makefile
// COMMON_API); apk_so_name/apk_list_sos are the two kept-global entry points.
#ifndef __ANUBEE_SYM_APK_H
#define __ANUBEE_SYM_APK_H

#include <stdint.h>

struct apk_so_ref {
	char     name[256];    // inner .so basename, e.g. "libnative.so"
	                       // AUDIT.md #6: matches apk_so_entry.name (sym_apk.c)
	                       // — was 128, which silently truncated basenames
	                       // >127 bytes read from the APK's own fname[256].
	char     abi[24];      // directory under lib/, e.g. "arm64-v8a"
	uint64_t data_start;   // ELF start byte offset within the APK
	uint64_t size;         // stored (compressed==uncompressed) size in bytes
};

// Return the inner .so basename for a stored .so mapped from an APK at elf_off
// (exact match only), or NULL if the path isn't an APK or elf_off matches no entry.
const char *apk_so_name(const char *path, uint64_t elf_off);

// Fill out[] with every stored lib/*/*.so entry in apk_path (up to max). Returns
// the count written, or 0 if the path isn't a readable APK / has no such entries.
int apk_list_sos(const char *apk_path, struct apk_so_ref *out, int max);

// Number of stored lib/*/*.so members of apk_path (0 if not a readable APK).
int apk_so_count(const char *apk_path);

// Copy member idx (0-based, central-directory order) into *out. Returns 1 on
// success, 0 if idx is out of range or the APK is unreadable.
int apk_so_get(const char *apk_path, int idx, struct apk_so_ref *out);

// Name of the member whose byte range [data_start, data_start+size) contains
// file_off, or NULL (not an APK, or no member). Unlike apk_so_name this is a
// range match, so any segment of a mapped member resolves. The pointer stays
// valid for the life of the process (it points into the per-APK cache).
const char *apk_so_at(const char *apk_path, uint64_t file_off);

// ELF start (data_start) of the stored member whose byte range contains
// file_off. Returns 1 and *data_start on a hit, 0 otherwise (not an APK, no
// member).
int apk_so_member_at(const char *apk_path, uint64_t file_off, uint64_t *data_start);

#endif /* __ANUBEE_SYM_APK_H */
