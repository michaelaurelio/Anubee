// SPDX-License-Identifier: GPL-2.0
// Pure helpers for the dexload-detect analyzer (src/modules/dexload_detect.c):
// payload magic classification, joining the kernel's leaf-first path
// components, finding a file's mapping in /proc/<pid>/maps, and saving a
// payload copy with its SHA-256. libc only -- host-testable.
#ifndef __ANUBEE_DEXLOAD_DETECT_PARSE_H
#define __ANUBEE_DEXLOAD_DETECT_PARSE_H

#include <stddef.h>

// Bytes per path component in dexload_detect_event.comp[] (mod_events.h's
// DEXLOAD_COMP_LEN; dexload_detect.c asserts they match).
#define DL_COMP_LEN 48

enum dl_kind {
    DL_NONE = 0,
    DL_DEX,      // "dex\n" + 3-digit version + NUL
    DL_CDEX,     // ART compact dex
    DL_ZIP,      // APK / JAR / plain zip -- indistinguishable from the header
    DL_ELF,      // native library or executable
    DL_KIND_N,
};

// Classify the first bytes written to a file. Needs n >= 4 (8 for dex,
// whose version digits are checked).
int dl_kind_of(const unsigned char *b, size_t n);
const char *dl_kind_name(int kind);   // "dex" "cdex" "zip" "elf", else "none"
const char *dl_kind_ext(int kind);    // file extension for a saved copy ("so" for elf)

// Whether a drop of this kind alerts on its own. A zip is too common
// (downloads, caches, backups) and alerts only once something maps it.
int dl_drop_alerts(int kind);

// Join n leaf-first components (comps + i*stride, each NUL-terminated) into
// "/root/.../leaf". truncated: the kernel walk stopped before the root, so
// the result is prefixed "..." instead of "/". Always NUL-terminates out.
void dl_path_join(const char *comps, int n, size_t stride, int truncated,
                  char *out, size_t cap);

// Find the first file-offset-0 mapping of inode `ino` in a /proc/<pid>/maps
// text. Returns 1 and sets [*start, *end) when found, else 0. Used to reach a
// mapped payload through /proc/<pid>/map_files after it is unlinked.
int dl_maps_find_ino(const char *maps, unsigned long ino,
                     unsigned long *start, unsigned long *end);

// The name of a memload region: maps_name (from /proc/<pid>/maps, without
// the "[anon:" wrapper) when it has one, else ev_name -- the name ART passed
// to prctl. The kernel rejects anon names over 80 bytes, which "dalvik-
// classes.dex extracted in memory from <path>" is for typical app paths, so
// the region stays unnamed and only the event knows what it holds.
const char *dl_memload_name(const char *maps_name, const char *ev_name);

// In-memory DEX (memload): a standard DEX header ("dex\n0NN\0", header_size
// 0x70, little-endian tag) whose file_size fits in a region of region_len
// bytes. n is how many header bytes were read (needs 0x70). Sets *file_size.
int dl_dex_header_ok(const unsigned char *h, size_t n, unsigned long region_len,
                     unsigned *file_size);

// Whether an ART DEX region (name without the "[anon:" wrapper) is worth
// reporting: "dalvik-DEX data" (a DEX loaded from memory) always;
// "dalvik-classes*.dex extracted in memory from <path>" unless <path> is on a
// read-only system partition (/system, /system_ext, /product, /vendor,
// /odm, /apex), in which case it is the platform's own code. *source is set
// to <path> (pointing into name) or NULL.
int dl_memload_wanted(const char *name, const char **source);

// "<dir>/<pid>-<ino>.<ext>"
void dl_payload_name(char *out, size_t cap, const char *dir, unsigned pid,
                     unsigned long long ino, int kind);

// Copy everything readable from in_fd (from its current offset) into a new
// file at dst (created/truncated, mode 0600), hashing as it goes. Returns
// bytes copied and fills sha_hex, or -1 on error (dst may be left partial).
long long dl_copy_fd(int in_fd, const char *dst, char sha_hex[65]);

#endif /* __ANUBEE_DEXLOAD_DETECT_PARSE_H */
