// SPDX-License-Identifier: GPL-2.0
// Host unit test for held library file descriptors (common/sym_fdhold.c):
// note/dup across a live process, dedup by (dev, inode), the fd cap and LRU
// eviction, and close-all.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include "common/maps.h"
#include "common/sym_fdhold.h"

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

// First mapped line with a real path and inode, from our own maps.
static int find_library_line(struct anubee_map_line *out)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[1024];

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        if (!anubee_parse_maps_line(line, out))
            continue;
        if (out->path[0] != '/' || out->inode == 0)
            continue;
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

// Opening a map_files entry needs ptrace access; report a permission-only miss.
static int map_files_denied(const struct anubee_map_line *l)
{
    char mf[96];
    int fd;

    anubee_map_files_path(mf, sizeof(mf), (int)getpid(), l->start, l->end);
    fd = open(mf, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return errno == EPERM || errno == EACCES;
}

static void test_note_then_dup(const struct anubee_map_line *l)
{
    struct stat st;
    int fd;

    fdhold_note((int)getpid(), l->start, l->end, l->inode, l->dev);
    fd = fdhold_dup(l->inode, l->dev);
    CHECK(fd >= 0, "note then dup returns a held fd");
    if (fd >= 0) {
        CHECK(fstat(fd, &st) == 0 && (uint64_t)st.st_ino == l->inode,
              "held fd is the mapped library");
        close(fd);
    }
}

static void test_dedup(const struct anubee_map_line *l)
{
    fdhold_close_all();
    fdhold_note((int)getpid(), l->start, l->end, l->inode, l->dev);
    fdhold_note((int)getpid(), l->start, l->end, l->inode, l->dev);
    CHECK(fdhold_count() == 1, "same dev/inode is held once");
}

static void test_cap(void)
{
    int fd;
    int i;

    fdhold_close_all();
    for (i = 0; i < 1030; i++) {
        fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;
        fdhold_put_fd((uint64_t)i + 1, 1, fd);
    }
    CHECK(fdhold_count() <= 1024, "fd count is capped");
    fd = fdhold_dup(1030, 1);
    CHECK(fd >= 0, "most recent key survives eviction");
    if (fd >= 0)
        close(fd);
}

static void test_close_all(void)
{
    fdhold_close_all();
    CHECK(fdhold_count() == 0, "close_all empties the table");
    CHECK(fdhold_dup(1030, 1) == -1, "close_all drops the held fds");
}

int main(void)
{
    struct anubee_map_line l;

    if (find_library_line(&l) != 0) {
        printf("FAIL: no file-backed library in /proc/self/maps\n");
        return 1;
    }

    if (map_files_denied(&l)) {
        printf("skip: map_files not readable for this user; skipping note/dup and dedup checks\n");
    } else {
        test_note_then_dup(&l);
        test_dedup(&l);
    }
    test_cap();
    test_close_all();

    if (fails) { printf("FAILED: %d check(s)\n", fails); return 1; }
    printf("test_fdhold: all checks passed\n");
    return 0;
}
