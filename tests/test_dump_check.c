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

    free(a);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
