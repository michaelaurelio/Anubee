// SPDX-License-Identifier: GPL-2.0
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "modules/payload_store.h"
#include "modules/dexload_detect_parse.h"   // dl_maps_find_ino
#include "common/proc_mem.h"
#include "common/sha256.h"

static char g_dir[512] = PAYLOAD_DIR_DEFAULT;
static int  g_state = 0;   // 0 untried, 1 ready, -1 failed

void payload_dir_init(const char *sink_path)
{
    if (sink_path) snprintf(g_dir, sizeof g_dir, "%s.payloads", sink_path);
    else           snprintf(g_dir, sizeof g_dir, "%s", PAYLOAD_DIR_DEFAULT);
    g_state = 0;
}

const char *payload_dir(void) { return g_dir; }

int payload_dir_ready(void)
{
    if (g_state) return g_state > 0;
    if (mkdir(g_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "mod: cannot create %s (%s) -- payload copies not saved\n",
                g_dir, strerror(errno));
        g_state = -1;
        return 0;
    }
    g_state = 1;
    return 1;
}

int payload_open_ino(const char *path, unsigned pid, unsigned long ino)
{
    struct stat st;
    int fd = path && path[0] ? open(path, O_RDONLY | O_CLOEXEC) : -1;
    if (fd >= 0) {
        if (fstat(fd, &st) == 0 && st.st_ino == ino) return fd;
        close(fd);
    }
    if (!pid) return -1;

    char p[96];
    snprintf(p, sizeof p, "/proc/%u/maps", pid);
    FILE *f = fopen(p, "r");
    if (f) {
        static char maps[1 << 20];
        size_t n = fread(maps, 1, sizeof maps - 1, f);
        fclose(f);
        maps[n] = '\0';
        unsigned long s, e;
        if (dl_maps_find_ino(maps, ino, &s, &e)) {
            snprintf(p, sizeof p, "/proc/%u/map_files/%lx-%lx", pid, s, e);
            fd = open(p, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) return fd;
        }
    }

    snprintf(p, sizeof p, "/proc/%u/fd", pid);
    DIR *d = opendir(p);
    if (!d) return -1;
    fd = -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char fp[300];
        snprintf(fp, sizeof fp, "/proc/%u/fd/%s", pid, de->d_name);
        if (stat(fp, &st) == 0 && st.st_ino == ino && S_ISREG(st.st_mode)) {
            fd = open(fp, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) break;
        }
    }
    closedir(d);
    return fd;
}

long long payload_save_region(unsigned pid, unsigned long va, unsigned long len,
                              const char *dst, char sha_hex[65],
                              unsigned char *head, size_t head_len, int *nonzero)
{
    if (nonzero) *nonzero = 0;
    int mem = proc_mem_open((int)pid);
    if (mem < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0) { close(mem); return -1; }
    struct sha256_ctx c;
    sha256_init(&c);
    static unsigned char buf[65536];
    long long total = 0;
    size_t got_head = 0;
    for (unsigned long off = 0; off < len; ) {
        size_t chunk = len - off < sizeof buf ? (size_t)(len - off) : sizeof buf;
        memset(buf, 0, chunk);
        size_t r = proc_mem_read(mem, (uint64_t)(va + off), buf, chunk);
        if (r == 0 && off == 0) break;   // nothing mapped there any more
        if (write(out, buf, chunk) != (ssize_t)chunk) { total = -1; break; }
        sha256_update(&c, buf, chunk);
        if (nonzero && !*nonzero)
            for (size_t i = 0; i < chunk; i++)
                if (buf[i]) { *nonzero = 1; break; }
        if (head && got_head < head_len) {
            size_t k = head_len - got_head < chunk ? head_len - got_head : chunk;
            memcpy(head + got_head, buf, k);
            got_head += k;
        }
        total += (long long)chunk;
        off += chunk;
    }
    close(mem);
    if (close(out) != 0) total = -1;
    if (total >= 0 && sha_hex) sha256_final_hex(&c, sha_hex);
    return total;
}
