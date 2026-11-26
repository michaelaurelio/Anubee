// SPDX-License-Identifier: GPL-2.0
// Held file handles of mapped libraries, keyed by (dev, inode). Thread safe.
#ifndef ANUBEE_SYM_FDHOLD_H
#define ANUBEE_SYM_FDHOLD_H

#include <stddef.h>
#include <stdint.h>

void   fdhold_note(int pid, uint64_t start, uint64_t end, uint64_t inode, uint32_t dev);
int    fdhold_dup(uint64_t inode, uint32_t dev);   // dup() of the held fd, or -1
void   fdhold_close_all(void);
size_t fdhold_count(void);                          // test/report helper
void   fdhold_put_fd(uint64_t inode, uint32_t dev, int fd);  // test helper: hold an fd you opened

#endif /* ANUBEE_SYM_FDHOLD_H */
