// SPDX-License-Identifier: GPL-2.0
// SO memory-dump repair — algorithm derived from F8LEFT/SoFixer.
// Fixes program headers, reconstructs section headers from PT_DYNAMIC,
// and un-applies RELATIVE relocations so the repaired file loads cleanly
// in IDA/Ghidra/readelf.

#include "so_repair.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// print functions shared with ares-tracer.c
extern void ts_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// ── bounds check ─────────────────────────────────────────────────────────────
// True if [off, off+sz) is entirely within a buffer of length `total`.
#define INBOUNDS(off, sz, total) \
    ((uint64_t)(off) <= (uint64_t)(total) && \
     (uint64_t)(sz)  <= (uint64_t)(total) - (uint64_t)(off))

// ── file helpers ─────────────────────────────────────────────────────────────

static uint8_t *file_read(const char *path, size_t *out_sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd); return NULL;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = malloc(sz);
    if (!buf) { close(fd); return NULL; }
    size_t done = 0;
    ssize_t n;
    while (done < sz && (n = read(fd, buf + done, sz - done)) > 0)
        done += (size_t)n;
    close(fd);
    if (done < sz) { free(buf); return NULL; }
    *out_sz = sz;
    return buf;
}

static int file_write(const char *path, const uint8_t *data, size_t sz)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t done = 0;
    ssize_t n;
    while (done < sz && (n = write(fd, data + done, sz - done)) > 0)
        done += (size_t)n;
    close(fd);
    return (done == sz) ? 0 : -1;
}

// ── section name string table ────────────────────────────────────────────────

#define SHSTR_CAP 1024

typedef struct { char buf[SHSTR_CAP]; size_t len; } shstr_t;

static void shstr_init(shstr_t *s) { s->buf[0] = '\0'; s->len = 1; }

static uint32_t shstr_add(shstr_t *s, const char *name)
{
    size_t n = strlen(name) + 1;
    if (s->len + n > SHSTR_CAP) return 0;
    uint32_t off = (uint32_t)s->len;
    memcpy(s->buf + s->len, name, n);
    s->len += n;
    return off;
}

// ── section descriptors ──────────────────────────────────────────────────────

#define SECT_MAX 14

typedef struct {
    const char *name;
    uint32_t    type;
    uint64_t    flags;
    uint64_t    addr;     // ELF-relative VA (= sh_addr and sh_offset in repaired file)
    uint64_t    size;
    uint64_t    entsize;
} sect_t;

static int sect_cmp(const void *a, const void *b)
{
    uint64_t aa = ((const sect_t *)a)->addr;
    uint64_t ab = ((const sect_t *)b)->addr;
    return (aa < ab) ? -1 : (aa > ab) ? 1 : 0;
}

// ── ELF64 (ARM64) repair ─────────────────────────────────────────────────────

// dump_base: lowest virtual address present in the dump (= runtime load base for PIE ELFs).
// Absolute VAs stored in DT_* entries are converted to dump offsets via:
//   dump_offset = abs_va - dump_base
// which equals the ELF-relative VA (sh_addr / sh_offset) for standard PIE SOs (min_vaddr=0).
// Program headers are fixed independently: p_offset = p_vaddr - min_vaddr.

static void repair64(const uint8_t *orig, size_t orig_sz,
                     uint64_t dump_base, const char *out_path)
{
    uint8_t *data = malloc(orig_sz);
    if (!data) return;
    memcpy(data, orig, orig_sz);

    uint8_t *out = NULL;
    int wrote = 0;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;

    // ── 1. scan PT_LOAD to get address bounds and phdr fix ────────────────

    if (!INBOUNDS(ehdr->e_phoff,
                  (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr), orig_sz))
        goto done;

    Elf64_Phdr *phdrs = (Elf64_Phdr *)(data + ehdr->e_phoff);
    uint64_t min_va = UINT64_MAX, max_va = 0;
    Elf64_Phdr *dyn_ph = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            if (phdrs[i].p_vaddr < min_va) min_va = phdrs[i].p_vaddr;
            uint64_t e = phdrs[i].p_vaddr + phdrs[i].p_memsz;
            if (e > max_va) max_va = e;
        }
        if (phdrs[i].p_type == PT_DYNAMIC) dyn_ph = &phdrs[i];
    }
    if (min_va == UINT64_MAX) min_va = 0;

    // p_vaddr is ELF-relative; dump_offset = p_vaddr - min_va
#define POFF(pv)  ((uint64_t)((pv) - min_va))
    // DT_ entries are absolute runtime VAs; ELF-relative VA = abs_va - dump_base
    // (correct for PIE where min_va == 0; generalises via min_va offset otherwise)
#define AOFF(av)  ((uint64_t)((av) >= dump_base ? (av) - dump_base : 0))

    for (int i = 0; i < ehdr->e_phnum; i++) {
        uint32_t t = phdrs[i].p_type;
        if (t == PT_LOAD || t == PT_DYNAMIC ||
            t == PT_GNU_RELRO || t == PT_GNU_STACK) {
            phdrs[i].p_offset = POFF(phdrs[i].p_vaddr);
            phdrs[i].p_filesz = phdrs[i].p_memsz;
            phdrs[i].p_paddr  = phdrs[i].p_vaddr;
        }
    }

    uint64_t load_size = (max_va > min_va) ? (max_va - min_va) : orig_sz;

    // ── 2. parse PT_DYNAMIC ───────────────────────────────────────────────

    uint64_t strtab_va = 0, strtab_sz = 0;
    uint64_t symtab_va = 0;
    uint64_t hash_va = 0, gnu_hash_va = 0;
    uint64_t rela_va = 0, rela_sz = 0;
    uint64_t plt_va  = 0, plt_sz  = 0;
    uint64_t init_va = 0, init_sz = 0;
    uint64_t fini_va = 0, fini_sz = 0;
    uint64_t dyn_va  = 0, dyn_sz  = 0;

    if (dyn_ph) {
        dyn_va = dyn_ph->p_vaddr;
        dyn_sz = dyn_ph->p_memsz;
        uint64_t doff = POFF(dyn_va);
        if (INBOUNDS(doff, dyn_sz, orig_sz)) {
            Elf64_Dyn *d = (Elf64_Dyn *)(data + doff);
            for (size_t i = 0; i < dyn_sz / sizeof(Elf64_Dyn) &&
                 d[i].d_tag != DT_NULL; i++) {
                switch ((int64_t)d[i].d_tag) {
                case DT_STRTAB:       strtab_va  = d[i].d_un.d_ptr; break;
                case DT_STRSZ:        strtab_sz  = d[i].d_un.d_val; break;
                case DT_SYMTAB:       symtab_va  = d[i].d_un.d_ptr; break;
                case DT_HASH:         hash_va    = d[i].d_un.d_ptr; break;
                case DT_GNU_HASH:     gnu_hash_va= d[i].d_un.d_ptr; break;
                case DT_RELA:         rela_va    = d[i].d_un.d_ptr; break;
                case DT_RELASZ:       rela_sz    = d[i].d_un.d_val; break;
                case DT_JMPREL:       plt_va     = d[i].d_un.d_ptr; break;
                case DT_PLTRELSZ:     plt_sz     = d[i].d_un.d_val; break;
                case DT_INIT_ARRAY:   init_va    = d[i].d_un.d_ptr; break;
                case DT_INIT_ARRAYSZ: init_sz    = d[i].d_un.d_val; break;
                case DT_FINI_ARRAY:   fini_va    = d[i].d_un.d_ptr; break;
                case DT_FINI_ARRAYSZ: fini_sz    = d[i].d_un.d_val; break;
                }
            }
        }
    }

    // dynsym size from .hash's nchain field (= total symbol count)
    uint64_t dynsym_sz = 0;
    uint64_t hash_sz   = 0;
    if (hash_va) {
        uint64_t ho = AOFF(hash_va);
        if (INBOUNDS(ho, 8, orig_sz)) {
            uint32_t nb = ((uint32_t *)(data + ho))[0];
            uint32_t nc = ((uint32_t *)(data + ho))[1];
            hash_sz   = (uint64_t)(2u + nb + nc) * 4;
            dynsym_sz = (uint64_t)nc * sizeof(Elf64_Sym);
        }
    }
    // Fallback: gap between symtab and strtab
    if (!dynsym_sz && symtab_va && strtab_va > symtab_va)
        dynsym_sz = strtab_va - symtab_va;

    // ── 3. fix R_AARCH64_RELATIVE relocations ────────────────────────────
    // After the linker runs, each RELATIVE slot = dump_base + addend.
    // Subtract dump_base to restore the original addend.

    if (dump_base) {
        uint64_t ranges[2][2] = { {rela_va, rela_sz}, {plt_va, plt_sz} };
        for (int p = 0; p < 2; p++) {
            uint64_t rv = ranges[p][0], rs = ranges[p][1];
            if (!rv || !rs) continue;
            uint64_t ro = AOFF(rv);
            if (!INBOUNDS(ro, rs, orig_sz)) continue;
            Elf64_Rela *r = (Elf64_Rela *)(data + ro);
            size_t cnt = rs / sizeof(Elf64_Rela);
            for (size_t i = 0; i < cnt; i++) {
                if (ELF64_R_TYPE(r[i].r_info) != R_AARCH64_RELATIVE) continue;
                uint64_t so = AOFF(r[i].r_offset);
                if (!INBOUNDS(so, sizeof(uint64_t), orig_sz)) continue;
                uint64_t *slot = (uint64_t *)(data + so);
                if (*slot >= dump_base) *slot -= dump_base;
            }
        }
    }

    // ── 4. build section descriptors ─────────────────────────────────────

    sect_t sects[SECT_MAX];
    int ns = 0;
    memset(sects, 0, sizeof(sects));

    // ELF-relative VA for each section = AOFF(abs_va) for DT_ values,
    // or POFF(p_vaddr) for phdr-derived sections.
#define ADDSECT(n, t, fl, rel_va, sz, es) do { \
    if ((rel_va) && ns < SECT_MAX) { \
        sects[ns].name    = (n);           \
        sects[ns].type    = (t);           \
        sects[ns].flags   = (fl);          \
        sects[ns].addr    = (rel_va);      \
        sects[ns].size    = (sz);          \
        sects[ns].entsize = (es);          \
        ns++;                              \
    }                                      \
} while(0)

    ADDSECT(".dynsym",    SHT_DYNSYM,    SHF_ALLOC,               AOFF(symtab_va),    dynsym_sz,      sizeof(Elf64_Sym));
    ADDSECT(".dynstr",    SHT_STRTAB,    SHF_ALLOC,               AOFF(strtab_va),    strtab_sz,      0);
    ADDSECT(".hash",      SHT_HASH,      SHF_ALLOC,               AOFF(hash_va),      hash_sz,        4);
    ADDSECT(".gnu.hash",  SHT_GNU_HASH,  SHF_ALLOC,               AOFF(gnu_hash_va),  0,              0);
    ADDSECT(".rela.dyn",  SHT_RELA,      SHF_ALLOC,               AOFF(rela_va),      rela_sz,        sizeof(Elf64_Rela));
    ADDSECT(".rela.plt",  SHT_RELA,      SHF_ALLOC|SHF_INFO_LINK, AOFF(plt_va),       plt_sz,         sizeof(Elf64_Rela));
    ADDSECT(".init_array",SHT_INIT_ARRAY,SHF_ALLOC|SHF_WRITE,     AOFF(init_va),      init_sz,        8);
    ADDSECT(".fini_array",SHT_FINI_ARRAY,SHF_ALLOC|SHF_WRITE,     AOFF(fini_va),      fini_sz,        8);
    ADDSECT(".dynamic",   SHT_DYNAMIC,   SHF_ALLOC|SHF_WRITE,     POFF(dyn_va),       dyn_sz,         sizeof(Elf64_Dyn));

    qsort(sects, ns, sizeof(sect_t), sect_cmp);

    // Fill zero-size sections using address gap to next known section
    for (int i = 0; i < ns; i++) {
        if (!sects[i].size) {
            uint64_t next = (i + 1 < ns) ? sects[i + 1].addr : load_size;
            if (next > sects[i].addr)
                sects[i].size = next - sects[i].addr;
        }
    }

    // ── 5. build .shstrtab and section index lookups ──────────────────────

    shstr_t shstr;
    shstr_init(&shstr);
    uint32_t name_offs[SECT_MAX] = {0};
    shstr_add(&shstr, "");  // offset 0 = empty name for null section
    for (int i = 0; i < ns; i++)
        name_offs[i] = shstr_add(&shstr, sects[i].name);
    uint32_t shstrtab_name = shstr_add(&shstr, ".shstrtab");

    // Section indices: 0=null, 1..ns=real sections, ns+1=.shstrtab
    int dynstr_idx = 0, dynsym_idx = 0;
    for (int i = 0; i < ns; i++) {
        if (!strcmp(sects[i].name, ".dynstr")) dynstr_idx = i + 1;
        if (!strcmp(sects[i].name, ".dynsym")) dynsym_idx = i + 1;
    }
    int shstrtab_idx = ns + 1;
    int total_shdrs  = ns + 2;   // null + real sections + .shstrtab

    // ── 6. assemble repaired file ─────────────────────────────────────────

    size_t shstr_sz   = shstr.len;
    size_t shdr_tbl   = (size_t)total_shdrs * sizeof(Elf64_Shdr);
    size_t out_sz     = load_size + shstr_sz + shdr_tbl;

    out = calloc(1, out_sz);
    if (!out) goto done;

    // Copy dump image (with phdr and reloc fixes already applied to `data`)
    size_t cp = orig_sz < load_size ? orig_sz : load_size;
    memcpy(out, data, cp);

    // Append section name string table
    memcpy(out + load_size, shstr.buf, shstr_sz);

    // Build section header table
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(out + load_size + shstr_sz);

    // [0] null section
    memset(&shdrs[0], 0, sizeof(Elf64_Shdr));

    // [1..ns] reconstructed sections
    for (int i = 0; i < ns; i++) {
        Elf64_Shdr *sh = &shdrs[i + 1];
        memset(sh, 0, sizeof(Elf64_Shdr));
        sh->sh_name      = name_offs[i];
        sh->sh_type      = sects[i].type;
        sh->sh_flags     = sects[i].flags;
        sh->sh_addr      = sects[i].addr;
        sh->sh_offset    = sects[i].addr;   // offset == ELF-relative VA for memory dumps
        sh->sh_size      = sects[i].size;
        sh->sh_entsize   = sects[i].entsize;
        sh->sh_addralign = sects[i].entsize > 1 ? sects[i].entsize : 1;

        uint32_t t = sects[i].type;
        if ((t == SHT_RELA || t == SHT_HASH || t == SHT_GNU_HASH) && dynsym_idx)
            sh->sh_link = (uint32_t)dynsym_idx;
        else if ((t == SHT_DYNSYM || t == SHT_DYNAMIC) && dynstr_idx)
            sh->sh_link = (uint32_t)dynstr_idx;

        // .dynsym: sh_info = index of first non-local (global) symbol
        if (t == SHT_DYNSYM) sh->sh_info = 1;
    }

    // [ns+1] .shstrtab
    {
        Elf64_Shdr *sh = &shdrs[ns + 1];
        memset(sh, 0, sizeof(Elf64_Shdr));
        sh->sh_name      = shstrtab_name;
        sh->sh_type      = SHT_STRTAB;
        sh->sh_offset    = (Elf64_Off)load_size;
        sh->sh_size      = (Elf64_Xword)shstr_sz;
        sh->sh_addralign = 1;
    }

    // Patch ELF header
    Elf64_Ehdr *out_eh = (Elf64_Ehdr *)out;
    out_eh->e_type       = ET_DYN;
    out_eh->e_shentsize  = sizeof(Elf64_Shdr);
    out_eh->e_shnum      = (uint16_t)total_shdrs;
    out_eh->e_shoff      = (Elf64_Off)(load_size + shstr_sz);
    out_eh->e_shstrndx   = (uint16_t)shstrtab_idx;

    if (file_write(out_path, out, out_sz) == 0) {
        ts_print(" [dump] > repaired  -> %s (%d sections)\n", out_path, ns + 1);
        wrote = 1;
    } else {
        err_print(" [dump] > repair write FAILED %s: %s\n", out_path, strerror(errno));
    }

done:
    if (!wrote && !out)
        err_print(" [dump] > repair FAILED (bad ELF or OOM): %s\n", out_path);
    free(out);
    free(data);
#undef POFF
#undef AOFF
#undef ADDSECT
}

// ── ELF32 (ARM32) repair ─────────────────────────────────────────────────────
// Same algorithm; ARM uses REL (not RELA) for most relocations.

static void repair32(const uint8_t *orig, size_t orig_sz,
                     uint32_t dump_base, const char *out_path)
{
    uint8_t *data = malloc(orig_sz);
    if (!data) return;
    memcpy(data, orig, orig_sz);

    uint8_t *out = NULL;
    int wrote = 0;

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;

    if (!INBOUNDS(ehdr->e_phoff,
                  (uint32_t)ehdr->e_phnum * sizeof(Elf32_Phdr), orig_sz))
        goto done;

    Elf32_Phdr *phdrs = (Elf32_Phdr *)(data + ehdr->e_phoff);
    uint32_t min_va = UINT32_MAX, max_va = 0;
    Elf32_Phdr *dyn_ph = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            if (phdrs[i].p_vaddr < min_va) min_va = phdrs[i].p_vaddr;
            uint32_t e = phdrs[i].p_vaddr + phdrs[i].p_memsz;
            if (e > max_va) max_va = e;
        }
        if (phdrs[i].p_type == PT_DYNAMIC) dyn_ph = &phdrs[i];
    }
    if (min_va == UINT32_MAX) min_va = 0;

#define POFF32(pv)  ((uint32_t)((pv) - min_va))
#define AOFF32(av)  ((uint32_t)((av) >= dump_base ? (av) - dump_base : 0))

    for (int i = 0; i < ehdr->e_phnum; i++) {
        uint32_t t = phdrs[i].p_type;
        if (t == PT_LOAD || t == PT_DYNAMIC ||
            t == PT_GNU_RELRO || t == PT_GNU_STACK) {
            phdrs[i].p_offset = POFF32(phdrs[i].p_vaddr);
            phdrs[i].p_filesz = phdrs[i].p_memsz;
            phdrs[i].p_paddr  = phdrs[i].p_vaddr;
        }
    }

    uint32_t load_size32 = (max_va > min_va) ? (max_va - min_va) : (uint32_t)orig_sz;

    // parse PT_DYNAMIC
    uint32_t strtab_va = 0, strtab_sz = 0;
    uint32_t symtab_va = 0;
    uint32_t hash_va = 0, gnu_hash_va = 0;
    uint32_t rel_va  = 0, rel_sz  = 0;   // DT_REL  (.rel.dyn)
    uint32_t plt_va  = 0, plt_sz  = 0;   // DT_JMPREL (.rel.plt)
    uint32_t init_va = 0, init_sz = 0;
    uint32_t fini_va = 0, fini_sz = 0;
    uint32_t dyn_va  = 0, dyn_sz  = 0;
    int use_rela = 0;
    uint32_t rela_va = 0, rela_sz_32 = 0;

    if (dyn_ph) {
        dyn_va = dyn_ph->p_vaddr;
        dyn_sz = dyn_ph->p_memsz;
        uint32_t doff = POFF32(dyn_va);
        if (INBOUNDS(doff, dyn_sz, orig_sz)) {
            Elf32_Dyn *d = (Elf32_Dyn *)(data + doff);
            for (size_t i = 0; i < dyn_sz / sizeof(Elf32_Dyn) &&
                 d[i].d_tag != DT_NULL; i++) {
                switch ((int32_t)d[i].d_tag) {
                case DT_STRTAB:       strtab_va  = d[i].d_un.d_ptr; break;
                case DT_STRSZ:        strtab_sz  = d[i].d_un.d_val; break;
                case DT_SYMTAB:       symtab_va  = d[i].d_un.d_ptr; break;
                case DT_HASH:         hash_va    = d[i].d_un.d_ptr; break;
                case DT_GNU_HASH:     gnu_hash_va= d[i].d_un.d_ptr; break;
                case DT_REL:          rel_va     = d[i].d_un.d_ptr; break;
                case DT_RELSZ:        rel_sz     = d[i].d_un.d_val; break;
                case DT_RELA:         rela_va    = d[i].d_un.d_ptr; use_rela = 1; break;
                case DT_RELASZ:       rela_sz_32 = d[i].d_un.d_val; break;
                case DT_JMPREL:       plt_va     = d[i].d_un.d_ptr; break;
                case DT_PLTRELSZ:     plt_sz     = d[i].d_un.d_val; break;
                case DT_INIT_ARRAY:   init_va    = d[i].d_un.d_ptr; break;
                case DT_INIT_ARRAYSZ: init_sz    = d[i].d_un.d_val; break;
                case DT_FINI_ARRAY:   fini_va    = d[i].d_un.d_ptr; break;
                case DT_FINI_ARRAYSZ: fini_sz    = d[i].d_un.d_val; break;
                }
            }
        }
    }

    uint32_t dynsym_sz32 = 0, hash_sz32 = 0;
    if (hash_va) {
        uint32_t ho = AOFF32(hash_va);
        if (INBOUNDS(ho, 8, orig_sz)) {
            uint32_t nb = ((uint32_t *)(data + ho))[0];
            uint32_t nc = ((uint32_t *)(data + ho))[1];
            hash_sz32   = (2u + nb + nc) * 4;
            dynsym_sz32 = nc * (uint32_t)sizeof(Elf32_Sym);
        }
    }
    if (!dynsym_sz32 && symtab_va && strtab_va > symtab_va)
        dynsym_sz32 = strtab_va - symtab_va;

    // fix R_ARM_RELATIVE relocations (type = 23)
#define R_ARM_RELATIVE 23
    if (dump_base) {
        // REL-style (most common for ARM)
        if (rel_va && rel_sz) {
            uint32_t ro = AOFF32(rel_va);
            if (INBOUNDS(ro, rel_sz, orig_sz)) {
                Elf32_Rel *r = (Elf32_Rel *)(data + ro);
                for (size_t i = 0; i < rel_sz / sizeof(Elf32_Rel); i++) {
                    if (ELF32_R_TYPE(r[i].r_info) != R_ARM_RELATIVE) continue;
                    uint32_t so = AOFF32(r[i].r_offset);
                    if (!INBOUNDS(so, sizeof(uint32_t), orig_sz)) continue;
                    uint32_t *slot = (uint32_t *)(data + so);
                    if (*slot >= dump_base) *slot -= dump_base;
                }
            }
        }
        // RELA-style (less common but supported)
        if (use_rela && rela_va && rela_sz_32) {
            uint32_t ro = AOFF32(rela_va);
            if (INBOUNDS(ro, rela_sz_32, orig_sz)) {
                Elf32_Rela *r = (Elf32_Rela *)(data + ro);
                for (size_t i = 0; i < rela_sz_32 / sizeof(Elf32_Rela); i++) {
                    if (ELF32_R_TYPE(r[i].r_info) != R_ARM_RELATIVE) continue;
                    uint32_t so = AOFF32(r[i].r_offset);
                    if (!INBOUNDS(so, sizeof(uint32_t), orig_sz)) continue;
                    uint32_t *slot = (uint32_t *)(data + so);
                    if (*slot >= dump_base) *slot -= dump_base;
                }
            }
        }
        // PLT relocations
        if (plt_va && plt_sz) {
            uint32_t ro = AOFF32(plt_va);
            if (INBOUNDS(ro, plt_sz, orig_sz)) {
                Elf32_Rel *r = (Elf32_Rel *)(data + ro);
                for (size_t i = 0; i < plt_sz / sizeof(Elf32_Rel); i++) {
                    if (ELF32_R_TYPE(r[i].r_info) != R_ARM_RELATIVE) continue;
                    uint32_t so = AOFF32(r[i].r_offset);
                    if (!INBOUNDS(so, sizeof(uint32_t), orig_sz)) continue;
                    uint32_t *slot = (uint32_t *)(data + so);
                    if (*slot >= dump_base) *slot -= dump_base;
                }
            }
        }
    }

    // build section descriptors
    sect_t sects[SECT_MAX];
    int ns = 0;
    memset(sects, 0, sizeof(sects));

#define ADDSECT32(n, t, fl, rel_va32, sz, es) do { \
    if ((rel_va32) && ns < SECT_MAX) { \
        sects[ns].name    = (n);           \
        sects[ns].type    = (t);           \
        sects[ns].flags   = (fl);          \
        sects[ns].addr    = (rel_va32);    \
        sects[ns].size    = (sz);          \
        sects[ns].entsize = (es);          \
        ns++;                              \
    }                                      \
} while(0)

    ADDSECT32(".dynsym",    SHT_DYNSYM,    SHF_ALLOC,               AOFF32(symtab_va),   dynsym_sz32,          sizeof(Elf32_Sym));
    ADDSECT32(".dynstr",    SHT_STRTAB,    SHF_ALLOC,               AOFF32(strtab_va),   strtab_sz,            0);
    ADDSECT32(".hash",      SHT_HASH,      SHF_ALLOC,               AOFF32(hash_va),     hash_sz32,            4);
    ADDSECT32(".gnu.hash",  SHT_GNU_HASH,  SHF_ALLOC,               AOFF32(gnu_hash_va), 0,                    0);
    ADDSECT32(".rel.dyn",   SHT_REL,       SHF_ALLOC,               AOFF32(rel_va),      rel_sz,               sizeof(Elf32_Rel));
    ADDSECT32(".rela.dyn",  SHT_RELA,      SHF_ALLOC,               AOFF32(rela_va),     rela_sz_32,           sizeof(Elf32_Rela));
    ADDSECT32(".rel.plt",   SHT_REL,       SHF_ALLOC|SHF_INFO_LINK, AOFF32(plt_va),      plt_sz,               sizeof(Elf32_Rel));
    ADDSECT32(".init_array",SHT_INIT_ARRAY,SHF_ALLOC|SHF_WRITE,     AOFF32(init_va),     init_sz,              4);
    ADDSECT32(".fini_array",SHT_FINI_ARRAY,SHF_ALLOC|SHF_WRITE,     AOFF32(fini_va),     fini_sz,              4);
    ADDSECT32(".dynamic",   SHT_DYNAMIC,   SHF_ALLOC|SHF_WRITE,     POFF32(dyn_va),      dyn_sz,               sizeof(Elf32_Dyn));

    qsort(sects, ns, sizeof(sect_t), sect_cmp);

    for (int i = 0; i < ns; i++) {
        if (!sects[i].size) {
            uint64_t next = (i + 1 < ns) ? sects[i + 1].addr : load_size32;
            if (next > sects[i].addr)
                sects[i].size = next - sects[i].addr;
        }
    }

    shstr_t shstr;
    shstr_init(&shstr);
    uint32_t name_offs[SECT_MAX] = {0};
    shstr_add(&shstr, "");
    for (int i = 0; i < ns; i++)
        name_offs[i] = shstr_add(&shstr, sects[i].name);
    uint32_t shstrtab_name = shstr_add(&shstr, ".shstrtab");

    int dynstr_idx = 0, dynsym_idx = 0;
    for (int i = 0; i < ns; i++) {
        if (!strcmp(sects[i].name, ".dynstr")) dynstr_idx = i + 1;
        if (!strcmp(sects[i].name, ".dynsym")) dynsym_idx = i + 1;
    }
    int shstrtab_idx = ns + 1;
    int total_shdrs  = ns + 2;

    size_t shstr_sz  = shstr.len;
    size_t shdr_tbl  = (size_t)total_shdrs * sizeof(Elf32_Shdr);
    size_t out_sz    = load_size32 + shstr_sz + shdr_tbl;

    out = calloc(1, out_sz);
    if (!out) goto done;

    size_t cp = orig_sz < load_size32 ? orig_sz : load_size32;
    memcpy(out, data, cp);
    memcpy(out + load_size32, shstr.buf, shstr_sz);

    Elf32_Shdr *shdrs = (Elf32_Shdr *)(out + load_size32 + shstr_sz);
    memset(&shdrs[0], 0, sizeof(Elf32_Shdr));

    for (int i = 0; i < ns; i++) {
        Elf32_Shdr *sh = &shdrs[i + 1];
        memset(sh, 0, sizeof(Elf32_Shdr));
        sh->sh_name      = name_offs[i];
        sh->sh_type      = sects[i].type;
        sh->sh_flags     = (Elf32_Word)sects[i].flags;
        sh->sh_addr      = (Elf32_Addr)sects[i].addr;
        sh->sh_offset    = (Elf32_Off)sects[i].addr;
        sh->sh_size      = (Elf32_Word)sects[i].size;
        sh->sh_entsize   = (Elf32_Word)sects[i].entsize;
        sh->sh_addralign = sects[i].entsize > 1 ? (Elf32_Word)sects[i].entsize : 1;

        uint32_t t = sects[i].type;
        if ((t == SHT_REL || t == SHT_RELA || t == SHT_HASH || t == SHT_GNU_HASH) && dynsym_idx)
            sh->sh_link = (uint32_t)dynsym_idx;
        else if ((t == SHT_DYNSYM || t == SHT_DYNAMIC) && dynstr_idx)
            sh->sh_link = (uint32_t)dynstr_idx;
        if (t == SHT_DYNSYM) sh->sh_info = 1;
    }

    {
        Elf32_Shdr *sh = &shdrs[ns + 1];
        memset(sh, 0, sizeof(Elf32_Shdr));
        sh->sh_name      = shstrtab_name;
        sh->sh_type      = SHT_STRTAB;
        sh->sh_offset    = (Elf32_Off)load_size32;
        sh->sh_size      = (Elf32_Word)shstr_sz;
        sh->sh_addralign = 1;
    }

    Elf32_Ehdr *out_eh = (Elf32_Ehdr *)out;
    out_eh->e_type       = ET_DYN;
    out_eh->e_shentsize  = sizeof(Elf32_Shdr);
    out_eh->e_shnum      = (uint16_t)total_shdrs;
    out_eh->e_shoff      = (Elf32_Off)(load_size32 + shstr_sz);
    out_eh->e_shstrndx   = (uint16_t)shstrtab_idx;

    if (file_write(out_path, out, out_sz) == 0) {
        ts_print(" [dump] > repaired  -> %s (%d sections)\n", out_path, ns + 1);
        wrote = 1;
    } else {
        err_print(" [dump] > repair write FAILED %s: %s\n", out_path, strerror(errno));
    }

done:
    if (!wrote && !out)
        err_print(" [dump] > repair FAILED (bad ELF or OOM): %s\n", out_path);
    free(out);
    free(data);
#undef POFF32
#undef AOFF32
#undef ADDSECT32
}

// ── public entry point ────────────────────────────────────────────────────────

void repair_dumped_so(const char *dump_path, uint64_t dump_base)
{
    size_t sz;
    uint8_t *data = file_read(dump_path, &sz);
    if (!data) {
        err_print(" [dump] > repair: cannot read %s\n", dump_path);
        return;
    }

    // Verify ELF magic
    if (sz < 16 || memcmp(data, "\x7f""ELF", 4) != 0) {
        err_print(" [dump] > repair: not an ELF file: %s\n", dump_path);
        free(data);
        return;
    }

    // Build output path: <dump_path>.fixed
    char out_path[512];
    int n = snprintf(out_path, sizeof(out_path), "%s.fixed", dump_path);
    if (n < 0 || (size_t)n >= sizeof(out_path)) {
        err_print(" [dump] > repair: output path too long\n");
        free(data);
        return;
    }

    if (data[EI_CLASS] == ELFCLASS64)
        repair64(data, sz, dump_base, out_path);
    else if (data[EI_CLASS] == ELFCLASS32)
        repair32(data, sz, (uint32_t)(dump_base & 0xffffffff), out_path);
    else
        err_print(" [dump] > repair: unknown ELF class %d\n", (int)data[EI_CLASS]);

    free(data);
}
