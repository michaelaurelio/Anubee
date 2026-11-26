// SPDX-License-Identifier: GPL-2.0
// Host unit test for the exec-only module base in common/sym_procmaps.c and
// the ELF program-header helper in common/sym_elf.c.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include "common/symbolize_internal.h"
#include "common/maps.h"

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

#define IMG_SIZE 0x3000
#define APK_DATA 0x40000
#define APK_ELF  0x41000

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

// pm_alloc_e calls this on eviction; symbolize.c owns the real hook.
void pm_evict_pid(int pid)
{
    (void)pid;
}

static void build_elf_image(uint8_t *img, uint64_t exec_vaddr)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)img;
    Elf64_Phdr *ph;

    memset(img, 0, IMG_SIZE);
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_type = ET_DYN;
    eh->e_machine = EM_AARCH64;
    eh->e_version = EV_CURRENT;
    eh->e_ehsize = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_phnum = 2;

    ph = (Elf64_Phdr *)(img + eh->e_phoff);
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R;
    ph[0].p_offset = 0;
    ph[0].p_vaddr = 0;
    ph[0].p_filesz = 0x1000;
    ph[0].p_memsz = 0x1000;
    ph[0].p_align = 0x1000;
    ph[1].p_type = PT_LOAD;
    ph[1].p_flags = PF_R | PF_X;
    ph[1].p_offset = 0x1000;
    ph[1].p_vaddr = exec_vaddr;
    ph[1].p_filesz = 0x1000;
    ph[1].p_memsz = 0x1000;
    ph[1].p_align = 0x1000;
}

static int write_bytes(const char *path, const void *buf, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    size_t w = fwrite(buf, 1, n, f);
    int r = (w == n) ? 0 : -1;
    if (fclose(f) != 0)
        r = -1;
    return r;
}

static void wle16(FILE *f, uint16_t v)
{
    fputc((int)(v & 0xff), f);
    fputc((int)((v >> 8) & 0xff), f);
}

static void wle32(FILE *f, uint32_t v)
{
    fputc((int)(v & 0xff), f);
    fputc((int)((v >> 8) & 0xff), f);
    fputc((int)((v >> 16) & 0xff), f);
    fputc((int)((v >> 24) & 0xff), f);
}

static int write_zeros(FILE *f, uint64_t n)
{
    static const uint8_t z[4096];

    while (n) {
        size_t k = n > sizeof(z) ? sizeof(z) : (size_t)n;

        if (fwrite(z, 1, k, f) != k)
            return -1;
        n -= k;
    }
    return 0;
}

// Stored ZIP containing one lib/arm64-v8a/libz.so whose data starts at APK_DATA.
static int write_apk(const char *path, const uint8_t *elf, size_t elfn)
{
    const char *name = "lib/arm64-v8a/libz.so";
    uint16_t nlen = (uint16_t)strlen(name);
    uint64_t lhdr_off = APK_DATA - 30 - nlen;
    int ok = 1;

    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;

    if (write_zeros(f, lhdr_off) != 0)
        ok = 0;
    if (ok) {
        wle32(f, 0x04034b50);
        wle16(f, 20);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 0);
        wle32(f, 0);
        wle32(f, (uint32_t)elfn);
        wle32(f, (uint32_t)elfn);
        wle16(f, nlen);
        wle16(f, 0);
        if (fwrite(name, 1, nlen, f) != nlen)
            ok = 0;
    }
    if (ok && fwrite(elf, 1, elfn, f) != elfn)
        ok = 0;

    long cd_off = ftell(f);
    if (cd_off < 0)
        ok = 0;
    if (ok) {
        wle32(f, 0x02014b50);
        wle16(f, 0);
        wle16(f, 20);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 0);
        wle32(f, 0);
        wle32(f, (uint32_t)elfn);
        wle32(f, (uint32_t)elfn);
        wle16(f, nlen);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 0);
        wle32(f, 0);
        wle32(f, (uint32_t)lhdr_off);
        if (fwrite(name, 1, nlen, f) != nlen)
            ok = 0;
    }
    long cd_end = ftell(f);
    if (cd_end < 0)
        ok = 0;
    if (ok) {
        wle32(f, 0x06054b50);
        wle16(f, 0);
        wle16(f, 0);
        wle16(f, 1);
        wle16(f, 1);
        wle32(f, (uint32_t)(cd_end - cd_off));
        wle32(f, (uint32_t)cd_off);
        wle16(f, 0);
    }
    if (ferror(f))
        ok = 0;
    if (fclose(f) != 0)
        ok = 0;
    return ok ? 0 : -1;
}

static struct procmaps *build_two_lines(int engine, int pid, const char *path,
                                        uint64_t off0, uint64_t off1)
{
    struct procmaps *pm = pm_alloc_e(engine, pid);
    struct anubee_map_line *m;

    if (!pm)
        return NULL;
    m = realloc(pm->m, 2 * sizeof(*m));
    if (!m)
        return NULL;
    pm->m = m;
    pm->cap = 2;
    pm->n = 2;

    memset(&pm->m[0], 0, sizeof(pm->m[0]));
    pm->m[0].start = 0x7000000000ULL;
    pm->m[0].end = 0x7000001000ULL;
    pm->m[0].off = off0;
    pm->m[0].exec = 0;
    snprintf(pm->m[0].path, sizeof(pm->m[0].path), "%s", path);
    pm->m[0].id = 0x100;
    pm->m[0].add_seq = 0;
    pm->m[0].del_seq = SYM_SEQ_LIVE;

    memset(&pm->m[1], 0, sizeof(pm->m[1]));
    pm->m[1].start = 0x7000001000ULL;
    pm->m[1].end = 0x7000002000ULL;
    pm->m[1].off = off1;
    pm->m[1].exec = 1;
    snprintf(pm->m[1].path, sizeof(pm->m[1].path), "%s", path);
    pm->m[1].id = 0x101;
    pm->m[1].add_seq = 0;
    pm->m[1].del_seq = SYM_SEQ_LIVE;

    return pm;
}

static void test_exec_base_plain(const char *path)
{
    int fd = open(path, O_RDONLY);
    uint64_t b = 0;

    CHECK(fd >= 0, "plain: open fixture");
    if (fd < 0)
        return;
    CHECK(elf_exec_load_base(fd, 0, 0x1000, 0x7000001000ULL, &b) == 0,
          "plain: exec segment matched");
    CHECK(b == 0x7000000000ULL, "plain: load base");
    close(fd);
}

static void test_exec_base_vaddr_offset(const char *path)
{
    int fd = open(path, O_RDONLY);
    uint64_t b = 0;

    CHECK(fd >= 0, "vaddr: open fixture");
    if (fd < 0)
        return;
    CHECK(elf_exec_load_base(fd, 0, 0x1000, 0x7000001000ULL, &b) == 0,
          "vaddr: exec segment matched");
    CHECK(b == 0x7000001000ULL - 0x11000ULL, "vaddr: load base honours p_vaddr");
    close(fd);
}

static void test_exec_base_in_apk(const char *path)
{
    int fd = open(path, O_RDONLY);
    uint64_t b = 0;

    CHECK(fd >= 0, "in-apk: open fixture");
    if (fd < 0)
        return;
    CHECK(elf_exec_load_base(fd, APK_DATA, APK_ELF, 0x7000001000ULL, &b) == 0,
          "in-apk: exec segment matched");
    CHECK(b == 0x7000000000ULL, "in-apk: load base");
    close(fd);
}

static void test_exec_base_no_match(const char *path)
{
    int fd = open(path, O_RDONLY);
    uint64_t b = 0;

    CHECK(fd >= 0, "no-match: open fixture");
    if (fd < 0)
        return;
    CHECK(elf_exec_load_base(fd, 0, 0x5000, 0x7000001000ULL, &b) == -1,
          "no-match: unknown segment rejected");
    close(fd);
}

static void test_module_base_exec_only_plain(const char *path)
{
    const int pid_a = 0x7ffffe01;
    const int pid_b = 0x7ffffe02;
    struct procmaps *pm_a, *pm_b;
    struct anubee_map_line *hit_a, *hit_b;
    uint64_t lba, eoa, bea, lbb, eob, beb;

    pm_apply_map(1, pid_a, 10, 0x7000001000ULL, 0x7000002000ULL,
                 1, 11, 1, path);
    pm_a = pm_find_e(1, pid_a);
    hit_a = pm_a ? find_mapping_at(pm_a, 0x7000001800ULL, SYM_SEQ_LIVE) : NULL;
    CHECK(hit_a != NULL, "plain model: exec line found");
    if (!hit_a)
        return;

    module_base_at(pm_a, hit_a, SYM_SEQ_LIVE, &lba, &eoa, &bea);
    CHECK(lba == 0x7000000000ULL && eoa == 0,
          "plain model: exec-only load base and elf offset");
    CHECK(hit_a->xstate == 1, "plain model: base cached");

    module_base_at(pm_a, hit_a, SYM_SEQ_LIVE, &lba, &eoa, &bea);
    CHECK(lba == 0x7000000000ULL && eoa == 0,
          "plain model: cached base reused");

    pm_b = build_two_lines(1, pid_b, path, 0, 0x1000);
    hit_b = pm_b ? find_mapping_at(pm_b, 0x7000001800ULL, SYM_SEQ_LIVE) : NULL;
    CHECK(hit_b != NULL, "plain walk model: exec line found");
    if (!hit_b)
        return;
    module_base_at(pm_b, hit_b, SYM_SEQ_LIVE, &lbb, &eob, &beb);
    CHECK(lba == lbb && eoa == eob,
          "plain model: exec-only result matches a full walk");
}

static void test_module_base_exec_only_apk(const char *apk)
{
    const int pid_c = 0x7ffffe03;
    const int pid_d = 0x7ffffe04;
    struct procmaps *pm_c, *pm_d;
    struct anubee_map_line *hit_c, *hit_d;
    uint64_t s = 0, lbc, eoc, bec, lbd, eod, bed;

    CHECK(apk_so_member_at(apk, APK_ELF, &s) == 1 && s == APK_DATA,
          "apk: member containing the exec offset found");

    pm_apply_map(1, pid_c, 10, 0x7000001000ULL, 0x7000002000ULL,
                 APK_ELF / 4096, 12, 1, apk);
    pm_c = pm_find_e(1, pid_c);
    hit_c = pm_c ? find_mapping_at(pm_c, 0x7000001800ULL, SYM_SEQ_LIVE) : NULL;
    CHECK(hit_c != NULL, "apk model: exec line found");
    if (!hit_c)
        return;

    module_base_at(pm_c, hit_c, SYM_SEQ_LIVE, &lbc, &eoc, &bec);
    CHECK(lbc == 0x7000000000ULL && eoc == APK_DATA,
          "apk model: exec-only load base and member offset");

    pm_d = build_two_lines(1, pid_d, apk, APK_DATA, APK_ELF);
    hit_d = pm_d ? find_mapping_at(pm_d, 0x7000001800ULL, SYM_SEQ_LIVE) : NULL;
    CHECK(hit_d != NULL, "apk walk model: exec line found");
    if (!hit_d)
        return;
    module_base_at(pm_d, hit_d, SYM_SEQ_LIVE, &lbd, &eod, &bed);
    CHECK(lbc == lbd && eoc == eod,
          "apk model: exec-only result matches a full walk");
}

static void test_module_base_seq_view(const char *path)
{
    const int pid_e = 0x7ffffe05;
    struct procmaps *pm_e;
    struct anubee_map_line *hit;
    uint64_t lb, eo, be;

    pm_e = build_two_lines(1, pid_e, path, 0, 0x1000);
    CHECK(pm_e != NULL, "seq view: model built");
    if (!pm_e)
        return;
    pm_apply_unmap(1, pid_e, 20, 0x7000000000ULL, 0x7000001000ULL);

    hit = find_mapping_at(pm_e, 0x7000001800ULL, 15);
    CHECK(hit != NULL, "seq view: exec line visible at seq 15");
    if (!hit)
        return;
    module_base_at(pm_e, hit, 15, &lb, &eo, &be);
    CHECK(lb == 0x7000000000ULL && eo == 0,
          "seq view: walk reaches the retired first segment");
    CHECK(hit->xstate == 0, "seq view: walk did not need the ELF cache");

    hit = find_mapping_at(pm_e, 0x7000001800ULL, SYM_SEQ_LIVE);
    CHECK(hit != NULL, "seq view: exec line visible at the live seq");
    if (!hit)
        return;
    module_base_at(pm_e, hit, SYM_SEQ_LIVE, &lb, &eo, &be);
    CHECK(lb == 0x7000000000ULL && eo == 0,
          "seq view: live exec-only derivation gives the same base");
    CHECK(hit->xstate == 1, "seq view: live derivation cached");
}

int main(void)
{
    char dir[] = "/tmp/anubee-elfXXXXXX";
    char plain[512], vaddr[512], container[512], apk[512];
    uint8_t *img, *big;
    int rc = 0;

    if (sysconf(_SC_PAGESIZE) != 4096) {
        printf("note: page size is not 4096, skipping test_elf_exec_base\n");
        return 0;
    }
    if (!mkdtemp(dir)) {
        printf("FAIL: mkdtemp\n");
        return 1;
    }
    snprintf(plain, sizeof(plain), "%s/plain.so", dir);
    snprintf(vaddr, sizeof(vaddr), "%s/vaddr.so", dir);
    snprintf(container, sizeof(container), "%s/container.bin", dir);
    snprintf(apk, sizeof(apk), "%s/x.apk", dir);

    img = malloc(IMG_SIZE);
    big = calloc(1, APK_DATA + IMG_SIZE);
    if (!img || !big) {
        printf("FAIL: fixture allocation\n");
        free(img);
        free(big);
        rmdir(dir);
        return 1;
    }

    build_elf_image(img, 0x1000);
    if (write_bytes(plain, img, IMG_SIZE) != 0)
        rc = -1;
    build_elf_image(img, 0x11000);
    if (write_bytes(vaddr, img, IMG_SIZE) != 0)
        rc = -1;
    build_elf_image(img, 0x1000);
    build_elf_image(big + APK_DATA, 0x1000);
    if (write_bytes(container, big, APK_DATA + IMG_SIZE) != 0)
        rc = -1;
    if (write_apk(apk, img, IMG_SIZE) != 0)
        rc = -1;

    CHECK(rc == 0, "fixtures written");
    if (rc == 0) {
        test_exec_base_plain(plain);
        test_exec_base_vaddr_offset(vaddr);
        test_exec_base_in_apk(container);
        test_exec_base_no_match(plain);
        test_module_base_exec_only_plain(plain);
        test_module_base_exec_only_apk(apk);
        test_module_base_seq_view(plain);
    }

    free(img);
    free(big);
    unlink(plain);
    unlink(vaddr);
    unlink(container);
    unlink(apk);
    rmdir(dir);

    if (fails) {
        printf("FAILED: %d check(s)\n", fails);
        return 1;
    }
    printf("test_elf_exec_base: all checks passed\n");
    return 0;
}
