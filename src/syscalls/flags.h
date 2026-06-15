/* flags.h
 *
 * Human-readable decoding of flag / enum syscall arguments (open flags, mmap
 * prot/flags, prctl option, signal numbers, socket domain/type, ...).
 */
#ifndef HEIMDALL_FLAGS_H
#define HEIMDALL_FLAGS_H

#include <stddef.h>

/* Decode argument `arg` (value `val`) of syscall number `nr` into `out`.
 * Returns 1 if a decoder applied, 0 otherwise (caller falls back to hex). */
int flags_decode_arg(long nr, int arg, unsigned long long val, char *out, size_t outsz);

#endif /* HEIMDALL_FLAGS_H */
