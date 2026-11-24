// SPDX-License-Identifier: GPL-2.0
// Trigger for the `mod fileless-detect` device smoke test
// (scripts/device-test.sh). No installed app does these things as part of
// normal operation -- that's the point of the signal -- so this is a
// purpose-built native binary, like massdelete-detect's/exfil-detect's
// generators. After a delay for the tracer to attach it does, in order:
//   1. anon_exec_mmap: mmap(MAP_ANONYMOUS, RWX), payload written in
//   2. mprotect_exec:  mmap(MAP_ANONYMOUS, RW), payload written, mprotect RX
//   3. memfd_exec:     memfd_create("anubee-stage2"), payload written, mmap RX
//   4. the same as 1 and 2 on regions named "dalvik-anubee-test" -- ART's
//      naming, which must NOT alert
// The payload is a recognisable ELF header plus a marker string.
#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

static const char payload[] = "\x7f" "ELF\x02\x01\x01" "anubee-fileless-payload";

static void name_region(void *p, size_t len, const char *name)
{
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (unsigned long)p, len, (unsigned long)name);
}

int main(void)
{
    sleep(3); // give the caller time to attach before the first mapping

    void *a = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (a == MAP_FAILED) return 1;
    memcpy(a, payload, sizeof payload);

    void *b = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (b == MAP_FAILED) return 1;
    memcpy(b, payload, sizeof payload);
    if (mprotect(b, 4096, PROT_READ | PROT_EXEC)) return 1;

    int fd = memfd_create("anubee-stage2", 0);
    if (fd < 0) return 1;
    if (write(fd, payload, sizeof payload) != (ssize_t)sizeof payload) return 1;
    void *c = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (c == MAP_FAILED) return 1;

    void *d = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (d != MAP_FAILED) name_region(d, 4096, "dalvik-anubee-test");
    void *e = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (e != MAP_FAILED) {
        name_region(e, 4096, "dalvik-anubee-test");
        memcpy(e, payload, sizeof payload);
        mprotect(e, 4096, PROT_READ | PROT_EXEC);
    }

    sleep(3); // keep everything mapped while the tracer reads and saves it
    return 0;
}
