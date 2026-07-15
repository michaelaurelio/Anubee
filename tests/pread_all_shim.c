// SPDX-License-Identifier: GPL-2.0
// Host-test definition of pread_all, which sym_apk.c calls and sym_elf.c
// normally provides. Linking sym_elf.c into these tests would drag in
// cfi_unwind.c and -llzma for one 6-line helper, so the dump host tests supply
// it directly - the same reasoning, and the same implementation, as
// tests/test_sym_apk.c:20, which links sym_apk.c standalone for this reason.
#include <unistd.h>
#include <sys/types.h>
#include <stddef.h>

int pread_all(int fd, void *buf, size_t n, off_t off);

int pread_all(int fd, void *buf, size_t n, off_t off)
{
    char *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r; off += r;
    }
    return 0;
}
