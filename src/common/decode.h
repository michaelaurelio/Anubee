/* decode.h — shared syscall-argument decoders (src/common).
 *
 * Human-readable decoding of flag / enum syscall arguments (open flags, mmap
 * prot/flags, prctl option, signal numbers, socket domain/type, ...) plus
 * sockaddr parsing and fd-path rendering.
 */
#ifndef __ANUBEE_DECODE_H
#define __ANUBEE_DECODE_H

#include <stddef.h>

/* Decode argument `arg` (value `val`) of syscall number `nr` into `out`.
 * Returns 1 if a decoder applied, 0 otherwise (caller falls back to hex). */
int flags_decode_arg(long nr, int arg, unsigned long long val, char *out, size_t outsz);

/* Decode a sockaddr blob (sa_family in host byte order) into out. Returns 1 on
 * success (AF_INET/AF_INET6/AF_UNIX rendered), 0 otherwise. */
int decode_sockaddr(const unsigned char *sa, unsigned len, char *out, size_t outsz);

/* Render fd `val` for process `pid` via /proc/<pid>/fd readlink into out. */
void render_fd(int pid, unsigned long long val, char *out, size_t outsz);

/* Invalidate the fd-path cache entry for (pid, fd); call on close(fd)==0. */
void fdc_drop(int pid, int fd);

#endif /* __ANUBEE_DECODE_H */
