// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the mod payload store: opening a file by inode (path,
// or an open fd after unlink), and saving a memory region of a live process
// through /proc/<pid>/mem -- run against this test process itself.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "modules/payload_store.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- open by inode -------------------------------------------------------
    char src[] = "/tmp/ps_srcXXXXXX";
    int fd = mkstemp(src);
    CHECK(fd >= 0 && write(fd, "payload!", 8) == 8, "temp file");
    struct stat st;
    fstat(fd, &st);

    int o = payload_open_ino(src, 0, st.st_ino);
    CHECK(o >= 0, "opened by path");
    if (o >= 0) close(o);
    CHECK(payload_open_ino(src, 0, st.st_ino + 1) < 0, "path with a different inode rejected");

    unlink(src);   // still open in this process
    o = payload_open_ino(src, (unsigned)getpid(), st.st_ino);
    CHECK(o >= 0, "unlinked file found through /proc/<pid>/fd");
    if (o >= 0) {
        char b[8];
        CHECK(pread(o, b, 8, 0) == 8 && memcmp(b, "payload!", 8) == 0, "right file");
        close(o);
    }
    close(fd);
    CHECK(payload_open_ino(src, (unsigned)getpid(), st.st_ino) < 0, "closed and unlinked -> gone");

    // ---- region save through /proc/<pid>/mem --------------------------------
    size_t len = 8192;
    unsigned char *r = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(r != MAP_FAILED, "region");
    memset(r, 0, len);
    memcpy(r, "abc", 3);
    char dst[] = "/tmp/ps_dstXXXXXX";
    close(mkstemp(dst));
    char sha[65] = "";
    unsigned char head[16];
    int nz = -1;
    long long n = payload_save_region((unsigned)getpid(), (unsigned long)r + 4096, 4096, dst, sha, head, sizeof head, &nz);
    CHECK(n == 4096 && nz == 0, "all-zero region reported as zero");
    r[6000] = 0x90;
    n = payload_save_region((unsigned)getpid(), (unsigned long)r + 4096, 4096, dst, sha, head, sizeof head, &nz);
    CHECK(nz == 1, "code after a zero head is still non-zero");
    n = payload_save_region((unsigned)getpid(), (unsigned long)r, 3, dst, sha, head, sizeof head, NULL);
    CHECK(n == 3, "saved 3 bytes");
    CHECK(strcmp(sha, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "sha256 of the region");
    CHECK(memcmp(head, "abc", 3) == 0, "head returned");
    n = payload_save_region((unsigned)getpid(), (unsigned long)r, len, dst, sha, head, sizeof head, NULL);
    CHECK(n == (long long)len, "whole region saved");
    CHECK(payload_save_region(0x7ffffff0u, 0x1000, 16, dst, sha, head, sizeof head, NULL) < 0,
          "no such process fails");
    unlink(dst);
    munmap(r, len);

    printf("test_payload_store: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
