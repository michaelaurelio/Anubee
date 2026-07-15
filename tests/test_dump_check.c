// SPDX-License-Identifier: GPL-2.0
// Host unit test for dump --check's comparison core. Builds synthetic ELF64
// images in memory (no device, no /proc) and pins the state machine.
//
// The rule under test that matters most: a short /proc/<pid>/mem read must
// report "unreadable", NEVER "differ". A partial read hashes wrong, and a false
// MODIFIED on a clean library destroys the tag's only value - trustworthiness.
#include "dump/rebuild.h"
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int checks = 0, failures = 0;
#define EQ(got, want, msg) do { checks++;                             \
    if (strcmp((got), (want)) != 0) { failures++;                     \
        printf("  FAIL: %s (got %s, want %s)\n", msg, (got), (want)); } \
} while (0)
#define CHECK(cond, msg) do { checks++;                               \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }         \
} while (0)

#define IMG_SZ   0x3000
#define TEXT_OFF 0x1000   // PF_X segment
#define TEXT_SZ  0x1000
#define DATA_OFF 0x2000   // PF_W segment (must be ignored)
#define DATA_SZ  0x1000

// Build a minimal ELF64 with one PF_X PT_LOAD and one PF_W PT_LOAD.
static unsigned char *mk_img(unsigned char text_fill, unsigned char data_fill)
{
    unsigned char *img = calloc(1, IMG_SZ);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)img;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_type = ET_DYN;
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 2;

    Elf64_Phdr *ph = (Elf64_Phdr *)(img + sizeof(Elf64_Ehdr));
    ph[0].p_type = PT_LOAD; ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = TEXT_OFF; ph[0].p_vaddr = TEXT_OFF;
    ph[0].p_filesz = TEXT_SZ; ph[0].p_memsz = TEXT_SZ;
    ph[1].p_type = PT_LOAD; ph[1].p_flags = PF_R | PF_W;
    ph[1].p_offset = DATA_OFF; ph[1].p_vaddr = DATA_OFF;
    ph[1].p_filesz = DATA_SZ; ph[1].p_memsz = DATA_SZ;

    memset(img + TEXT_OFF, text_fill, TEXT_SZ);
    memset(img + DATA_OFF, data_fill, DATA_SZ);
    return img;
}

// ---- minimal stored-entry ZIP writer, for dump_read_apk_member below ------
//
// Mirrors the stored-entry writer in tests/test_sym_apk.c (which pins
// common/sym_apk.c's central-directory reader); this is a local, single-entry
// version so this file doesn't share statics with that one.

#define ZBUF_CAP 512
static unsigned char zbuf[ZBUF_CAP];
static size_t zpos;

static void put_bytes(const void *p, size_t n) { memcpy(zbuf + zpos, p, n); zpos += n; }
static void put_le16(uint16_t v) {
    unsigned char b[2] = { (unsigned char)v, (unsigned char)(v >> 8) };
    put_bytes(b, 2);
}
static void put_le32(uint32_t v) {
    unsigned char b[4] = { (unsigned char)v, (unsigned char)(v >> 8),
                            (unsigned char)(v >> 16), (unsigned char)(v >> 24) };
    put_bytes(b, 4);
}

int main(void)
{
    char mh[65], fh[65];

    // --- identical images -> match ---
    unsigned char *a = mk_img(0xAA, 0x11);
    unsigned char *b = mk_img(0xAA, 0x11);
    EQ(dump_check_image(a, IMG_SZ, b, IMG_SZ, mh, fh), "match", "identical -> match");
    CHECK(strcmp(mh, fh) == 0, "identical -> equal digests");
    free(b);

    // --- .data differs, .text identical -> STILL match ---
    // This is load-bearing: .data/.got/.data.rel.ro are rewritten by the linker
    // on every load. Hashing them would report differ for every library.
    b = mk_img(0xAA, 0x99);
    EQ(dump_check_image(a, IMG_SZ, b, IMG_SZ, mh, fh), "match",
       "writable-segment difference is ignored");
    free(b);

    // --- .text differs -> differ ---
    b = mk_img(0xBB, 0x11);
    EQ(dump_check_image(a, IMG_SZ, b, IMG_SZ, mh, fh), "differ", "exec difference -> differ");
    CHECK(strcmp(mh, fh) != 0, "differ -> digests differ");
    free(b);

    // --- short memory buffer -> unreadable, never differ ---
    b = mk_img(0xAA, 0x11);
    EQ(dump_check_image(a, TEXT_OFF + 4, b, IMG_SZ, mh, fh), "unreadable",
       "truncated memory image -> unreadable");
    // --- short file buffer -> unreadable too (no baseline to compare) ---
    EQ(dump_check_image(a, IMG_SZ, b, TEXT_OFF + 4, mh, fh), "unreadable",
       "truncated file image -> unreadable");
    free(b);

    // --- garbage (no ELF magic) -> unreadable ---
    unsigned char junk[IMG_SZ];
    memset(junk, 0x5A, sizeof(junk));
    EQ(dump_check_image(junk, IMG_SZ, junk, IMG_SZ, mh, fh), "unreadable",
       "no ELF header -> unreadable");

    // --- a crafted phdr must not defeat the bounds checks (integer overflow) ---
    // dump --check reads bytes from a potentially hostile .so, so p_offset and
    // p_filesz are attacker-controlled. A p_offset near UINT64_MAX makes
    // p_offset + p_filesz wrap to a small value, so a naive `> len` check passes
    // and the code then reads img + p_offset, out of bounds. Without ASan that
    // usually does not crash - it silently hashes adjacent heap, and the wrong
    // digest can surface as "differ": a false MODIFIED on an intact library.
    unsigned char *ov = mk_img(0xAA, 0x11);
    Elf64_Phdr *ovp = (Elf64_Phdr *)(ov + sizeof(Elf64_Ehdr));
    ovp[0].p_offset = (uint64_t)-100;
    ovp[0].p_filesz = 200;
    EQ(dump_check_image(ov, IMG_SZ, ov, IMG_SZ, mh, fh), "unreadable",
       "wrapped p_offset + p_filesz -> unreadable, not an OOB read");
    free(ov);

    // Same wrap, one level up: the phdr table's own offset.
    unsigned char *oe = mk_img(0xAA, 0x11);
    ((Elf64_Ehdr *)oe)->e_phoff = (uint64_t)-10;
    EQ(dump_check_image(oe, IMG_SZ, oe, IMG_SZ, mh, fh), "unreadable",
       "wrapped e_phoff -> unreadable, not an OOB read");
    free(oe);

    // --- dump_read_apk_member: exact-offset stored-member resolution -------
    // extractNativeLibs=false (the modern AGP default) maps a stored .so
    // straight out of base.apk, so this is what dump --check's "apk" branch
    // relies on to get a baseline at all. Build a minimal single-entry stored
    // ZIP on disk and pin the exact-match behavior: an inverted offset
    // comparison, an off-by-one in the size guard, or a broken seek/read would
    // all sail through here undetected without this.
    {
        const char *ename = "lib/arm64-v8a/libfixture.so";
        uint16_t nlen = (uint16_t)strlen(ename);
        const unsigned char payload[] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b
        };
        uint32_t plen = (uint32_t)sizeof(payload);
        unsigned char *got;
        size_t got_len;

        zpos = 0;
        uint32_t lhdr_off = (uint32_t)zpos;
        put_le32(0x04034b50);   // local file header signature
        put_le16(20);            // version needed
        put_le16(0);              // flags
        put_le16(0);              // method: 0 = stored
        put_le16(0);              // mod time
        put_le16(0);              // mod date
        put_le32(0);              // crc32 (unchecked by the reader)
        put_le32(plen);           // compressed size
        put_le32(plen);           // uncompressed size
        put_le16(nlen);           // filename length
        put_le16(0);               // extra length
        put_bytes(ename, nlen);
        uint32_t data_start = (uint32_t)zpos;
        put_bytes(payload, plen);

        uint32_t cd_off = (uint32_t)zpos;
        put_le32(0x02014b50);   // central directory signature
        put_le16(0);              // version made by
        put_le16(20);             // version needed
        put_le16(0);              // flags
        put_le16(0);              // method: 0 = stored
        put_le16(0);              // mod time
        put_le16(0);              // mod date
        put_le32(0);              // crc32
        put_le32(plen);           // compressed size
        put_le32(plen);           // uncompressed size
        put_le16(nlen);           // filename length
        put_le16(0);               // extra length
        put_le16(0);               // comment length
        put_le16(0);               // disk number start
        put_le16(0);               // internal attrs
        put_le32(0);               // external attrs
        put_le32(lhdr_off);       // local header offset
        put_bytes(ename, nlen);
        uint32_t cd_size = (uint32_t)zpos - cd_off;

        put_le32(0x06054b50);   // EOCD signature
        put_le16(0);              // disk number
        put_le16(0);              // disk with CD
        put_le16(1);              // entries on this disk
        put_le16(1);              // total entries
        put_le32(cd_size);        // CD size
        put_le32(cd_off);         // CD offset
        put_le16(0);               // comment length

        char apk_path[] = "/tmp/test_dump_check_apk_XXXXXX";
        int afd = mkstemp(apk_path);
        CHECK(afd >= 0, "apk fixture: mkstemp");
        if (afd >= 0) {
            ssize_t w = write(afd, zbuf, zpos);
            CHECK((size_t)w == zpos, "apk fixture: write full buffer");
            close(afd);

            // exact data_start -> the member's exact bytes and length
            got_len = 0;
            got = dump_read_apk_member(apk_path, data_start, &got_len);
            CHECK(got != NULL, "apk member: exact offset hit returns non-NULL");
            if (got) {
                CHECK(got_len == plen, "apk member: exact offset hit returns correct length");
                CHECK(memcmp(got, payload, plen) == 0,
                      "apk member: exact offset hit returns correct content");
                free(got);
            }

            // an offset matching no member -> NULL
            got = dump_read_apk_member(apk_path, data_start + 4096, &got_len);
            CHECK(got == NULL, "apk member: offset matching no member returns NULL");

            // an offset one byte off from the real data_start -> NULL: the match
            // must be exact, never nearest, or a range/prefix match would resolve
            // the wrong library.
            got = dump_read_apk_member(apk_path, data_start + 1, &got_len);
            CHECK(got == NULL, "apk member: off-by-one offset returns NULL");

            unlink(apk_path);
        }

        // a non-existent path -> NULL. mkstemp for a unique name, then delete it
        // right away, so this can't collide with a real file left by another run.
        {
            char nopath[] = "/tmp/test_dump_check_apk_nonexist_XXXXXX";
            int tmpfd = mkstemp(nopath);
            CHECK(tmpfd >= 0, "non-existent-path fixture: mkstemp");
            if (tmpfd >= 0) {
                close(tmpfd);
                unlink(nopath);
                got = dump_read_apk_member(nopath, data_start, &got_len);
                CHECK(got == NULL, "apk member: non-existent path returns NULL");
            }
        }

        // a path that exists but is not a ZIP -> NULL
        {
            char notzip_path[] = "/tmp/test_dump_check_notzip_XXXXXX";
            int nfd = mkstemp(notzip_path);
            CHECK(nfd >= 0, "non-ZIP fixture: mkstemp");
            if (nfd >= 0) {
                const char *junk = "this is not a zip archive, just plain text padding";
                ssize_t w2 = write(nfd, junk, strlen(junk));
                CHECK((size_t)w2 == strlen(junk), "non-ZIP fixture: write");
                close(nfd);

                got = dump_read_apk_member(notzip_path, data_start, &got_len);
                CHECK(got == NULL, "apk member: non-ZIP path returns NULL");

                unlink(notzip_path);
            }
        }
    }

    free(a);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
