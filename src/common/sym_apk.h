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
	uint64_t data_start;   // ELF start byte offset within the APK
	uint64_t size;         // stored (compressed==uncompressed) size in bytes
};

// Return the inner .so basename for a stored .so mapped from an APK at elf_off
// (exact match only), or NULL if the path isn't an APK or elf_off matches no entry.
const char *apk_so_name(const char *path, uint64_t elf_off);

// Fill out[] with every stored lib/*/*.so entry in apk_path (up to max). Returns
// the count written, or 0 if the path isn't a readable APK / has no such entries.
int apk_list_sos(const char *apk_path, struct apk_so_ref *out, int max);

#endif /* __ANUBEE_SYM_APK_H */
