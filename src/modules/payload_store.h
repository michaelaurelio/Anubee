// SPDX-License-Identifier: GPL-2.0
// Where `mod` analyzers keep copies of payloads they catch (dexload-detect's
// dropped files, fileless-detect's executable regions), and the readers that
// get at them: a file by inode (path, else /proc/<pid>/map_files after
// unlink, else an open fd) and a live region through /proc/<pid>/mem. Every
// read is anubee's own I/O -- nothing is written into the target.
#ifndef __ANUBEE_PAYLOAD_STORE_H
#define __ANUBEE_PAYLOAD_STORE_H

#include <stddef.h>

// Directory: "<sink_path>.payloads" with -o, else PAYLOAD_DIR_DEFAULT. Set
// once at setup; created (0700) on first use.
#define PAYLOAD_DIR_DEFAULT "/data/local/tmp/anubee-payloads"
void        payload_dir_init(const char *sink_path);
const char *payload_dir(void);
int         payload_dir_ready(void);   // 1 = usable (created now or before)

// A read-only fd on the file with inode `ino`: `path` (may be NULL), then the
// mapping in /proc/<pid>/map_files, then /proc/<pid>/fd. -1 if not reachable.
int payload_open_ino(const char *path, unsigned pid, unsigned long ino);

// Copy [va, va+len) of process pid into a new file dst (0600) and hash it.
// Unreadable pages are skipped. head (may be NULL) receives the first
// min(len, head_len) bytes; *nonzero (may be NULL) is set to whether any
// byte read was non-zero. Returns bytes read (0 = nothing readable), or -1
// when the process or dst can't be opened.
long long payload_save_region(unsigned pid, unsigned long va, unsigned long len,
                              const char *dst, char sha_hex[65],
                              unsigned char *head, size_t head_len, int *nonzero);

#endif /* __ANUBEE_PAYLOAD_STORE_H */
