#include "common/cfi_unwind.h"
#include "common/dwarf.h"

#include <elf.h>
#include <stdlib.h>
#include <string.h>

/* forward declarations — defined later in this file */
static int fde_cmp(const void *a, const void *b);
static int parse_cie(const uint8_t *data, size_t len, uint32_t cie_off, struct cfi_cie *out);

/* ---------------------------------------------------------------------------
 * cfi_extract_debug_frame: locate ".debug_frame" inside an ELF64 image.
 * Every offset is untrusted and bounds-checked against len.
 * -------------------------------------------------------------------------*/
int cfi_extract_debug_frame(const uint8_t *elf, size_t len,
                            const uint8_t **df, size_t *df_len)
{
    /* Minimum size for a valid ELF64 header */
    if (len < sizeof(Elf64_Ehdr))
        return -1;

    Elf64_Ehdr ehdr;
    memcpy(&ehdr, elf, sizeof(Elf64_Ehdr));

    /* Validate ELF magic */
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3)
        return -1;

    /* Only ELF64 supported */
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64)
        return -1;

    /* Validate section header table: offset, count, entry size */
    if (ehdr.e_shnum == 0 || ehdr.e_shentsize < sizeof(Elf64_Shdr))
        return -1;

    /* Check e_shoff + total section header table fits in the image */
    uint64_t shoff = ehdr.e_shoff;
    uint64_t shnum = ehdr.e_shnum;
    uint64_t shentsz = ehdr.e_shentsize;
    if (shoff == 0 || shoff > len)
        return -1;
    /* shnum * shentsz may overflow; check with division */
    if (shentsz != 0 && shnum > (len - shoff) / shentsz)
        return -1;

    /* Validate e_shstrndx */
    uint16_t shstrndx = ehdr.e_shstrndx;
    if (shstrndx >= shnum)
        return -1;

    /* Read the section-header string table section header */
    Elf64_Shdr shstr_hdr;
    uint64_t shstr_hdr_off = shoff + (uint64_t)shstrndx * shentsz;
    if (shstr_hdr_off + sizeof(Elf64_Shdr) > len)
        return -1;
    memcpy(&shstr_hdr, elf + shstr_hdr_off, sizeof(Elf64_Shdr));

    /* Validate shstrtab section content bounds */
    uint64_t shstr_off  = shstr_hdr.sh_offset;
    uint64_t shstr_size = shstr_hdr.sh_size;
    if (shstr_size == 0 || shstr_off > len || shstr_off + shstr_size > len)
        return -1;

    const char *shstr = (const char *)(elf + shstr_off);

    /* Walk section headers looking for ".debug_frame" */
    static const char target[] = ".debug_frame";
    for (uint64_t i = 0; i < shnum; i++) {
        uint64_t sh_off = shoff + i * shentsz;
        if (sh_off + sizeof(Elf64_Shdr) > len)
            return -1;

        Elf64_Shdr shdr;
        memcpy(&shdr, elf + sh_off, sizeof(Elf64_Shdr));

        /* Bounds-check sh_name against the string table */
        if ((uint64_t)shdr.sh_name >= shstr_size)
            continue;

        /* Compare name */
        /* Ensure the full name+NUL is within shstrtab: the memcmp below reads
         * sizeof(target) bytes (including the terminator) for an exact match. */
        size_t max_name = (size_t)(shstr_size - shdr.sh_name);
        if (max_name < sizeof(target))
            continue;
        if (memcmp(shstr + shdr.sh_name, target, sizeof(target)) != 0)
            continue;

        /* Found ".debug_frame" — bounds-check its content */
        uint64_t sec_off  = shdr.sh_offset;
        uint64_t sec_size = shdr.sh_size;
        if (sec_size == 0 || sec_off > len || sec_off + sec_size > len)
            return -1;

        *df     = elf + sec_off;
        *df_len = (size_t)sec_size;
        return 0;
    }

    return -1; /* no ".debug_frame" section found */
}

/* ---------------------------------------------------------------------------
 * cfi_extract_eh_frame: locate ".eh_frame" inside an ELF64 image and return
 * the section virtual address (sh_addr) needed for pcrel FDE pointer decoding.
 * Same bounds discipline as cfi_extract_debug_frame.
 * -------------------------------------------------------------------------*/
int cfi_extract_eh_frame(const uint8_t *elf, size_t len,
                         const uint8_t **eh, size_t *eh_len, uint64_t *eh_vaddr)
{
    if (len < sizeof(Elf64_Ehdr))
        return -1;

    Elf64_Ehdr ehdr;
    memcpy(&ehdr, elf, sizeof(Elf64_Ehdr));

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3)
        return -1;

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64)
        return -1;

    if (ehdr.e_shnum == 0 || ehdr.e_shentsize < sizeof(Elf64_Shdr))
        return -1;

    uint64_t shoff   = ehdr.e_shoff;
    uint64_t shnum   = ehdr.e_shnum;
    uint64_t shentsz = ehdr.e_shentsize;
    if (shoff == 0 || shoff > len)
        return -1;
    if (shentsz != 0 && shnum > (len - shoff) / shentsz)
        return -1;

    uint16_t shstrndx = ehdr.e_shstrndx;
    if (shstrndx >= shnum)
        return -1;

    Elf64_Shdr shstr_hdr;
    uint64_t shstr_hdr_off = shoff + (uint64_t)shstrndx * shentsz;
    if (shstr_hdr_off + sizeof(Elf64_Shdr) > len)
        return -1;
    memcpy(&shstr_hdr, elf + shstr_hdr_off, sizeof(Elf64_Shdr));

    uint64_t shstr_off  = shstr_hdr.sh_offset;
    uint64_t shstr_size = shstr_hdr.sh_size;
    if (shstr_size == 0 || shstr_off > len || shstr_off + shstr_size > len)
        return -1;

    const char *shstr = (const char *)(elf + shstr_off);

    static const char target[] = ".eh_frame";
    for (uint64_t i = 0; i < shnum; i++) {
        uint64_t sh_off = shoff + i * shentsz;
        if (sh_off + sizeof(Elf64_Shdr) > len)
            return -1;

        Elf64_Shdr shdr;
        memcpy(&shdr, elf + sh_off, sizeof(Elf64_Shdr));

        if ((uint64_t)shdr.sh_name >= shstr_size)
            continue;

        size_t max_name = (size_t)(shstr_size - shdr.sh_name);
        if (max_name < sizeof(target))
            continue;
        if (memcmp(shstr + shdr.sh_name, target, sizeof(target)) != 0)
            continue;

        uint64_t sec_off  = shdr.sh_offset;
        uint64_t sec_size = shdr.sh_size;
        if (sec_size == 0 || sec_off > len || sec_off + sec_size > len)
            return -1;

        *eh       = elf + sec_off;
        *eh_len   = (size_t)sec_size;
        *eh_vaddr = shdr.sh_addr;
        return 0;
    }

    return -1; /* no ".eh_frame" section found */
}

/* ---------------------------------------------------------------------------
 * decode_eh_pe: decode one DW_EH_PE-encoded value from *c.
 *
 * enc        : the encoding byte from the CIE's 'R' augmentation.
 * field_vaddr: the virtual address of the first byte of this field in memory
 *              (= section_vaddr + current section-offset BEFORE the read).
 *              Used only for the pcrel application (enc & 0x70) == 0x10.
 * apply_pcrel: if 0, only the FORMAT part is decoded (used for address_range).
 * *val_out   : receives the decoded value.
 *
 * Returns 0 on success, -1 on unsupported encoding or read error.
 * -------------------------------------------------------------------------*/
static int decode_eh_pe(struct dwarf_cur *c, uint8_t enc,
                        uint64_t field_vaddr, int apply_pcrel,
                        uint64_t *val_out)
{
    /* DW_EH_PE_omit */
    if (enc == 0xff) {
        *val_out = 0;
        return 0;
    }

    uint8_t fmt = enc & 0x0fu;
    uint8_t app = enc & 0x70u;

    uint64_t val;
    switch (fmt) {
    case 0x00: /* absptr = udata8 on 64-bit */
        val = dwarf_u64(c);
        break;
    case 0x01: /* uleb128 */
        val = dwarf_uleb(c);
        break;
    case 0x02: /* udata2 */
        val = dwarf_u16(c);
        break;
    case 0x03: /* udata4 */
        val = dwarf_u32(c);
        break;
    case 0x04: /* udata8 */
        val = dwarf_u64(c);
        break;
    case 0x09: /* sleb128 */
        val = (uint64_t)dwarf_sleb(c);
        break;
    case 0x0a: { /* sdata2 */
        uint16_t raw = dwarf_u16(c);
        int16_t  s   = (int16_t)raw;
        val = (uint64_t)(int64_t)s;
        break;
    }
    case 0x0b: { /* sdata4 */
        uint32_t raw = dwarf_u32(c);
        int32_t  s   = (int32_t)raw;
        val = (uint64_t)(int64_t)s;
        break;
    }
    case 0x0c: { /* sdata8 */
        uint64_t raw = dwarf_u64(c);
        val = raw; /* already sign-extended in 64-bit */
        break;
    }
    default:
        return -1;
    }

    if (c->err)
        return -1;

    /* Apply relocation */
    if (apply_pcrel) {
        switch (app) {
        case 0x00: /* absolute — no adjustment */
            break;
        case 0x10: /* pcrel — add field_vaddr */
            val += field_vaddr;
            break;
        default:
            return -1; /* unsupported application */
        }
    }

    *val_out = val;
    return 0;
}

/* ---------------------------------------------------------------------------
 * cfi_parse_eh_frame: two-pass parse of a .eh_frame section.
 * Same structure as cfi_parse_debug_frame but uses eh entry conventions:
 *   - id == 0  => CIE; id != 0 => FDE with cie_off = (id_field_offset) - id
 *   - FDE initial_location decoded via DW_EH_PE from CIE's fde_enc
 *   - section_vaddr stored on the section for cfi_read_cie to later use
 * -------------------------------------------------------------------------*/
int cfi_parse_eh_frame(struct cfi_section *s, const uint8_t *data, size_t len,
                       uint64_t section_vaddr)
{
    s->data         = data;
    s->len          = len;
    s->fdes         = NULL;
    s->nfde         = 0;
    s->section_vaddr = section_vaddr;
    s->owned        = NULL;   /* not heap-owned here; cfi_section_free frees this */

    /* First pass: count FDEs */
    size_t nfde = 0;
    {
        struct dwarf_cur c;
        dwarf_cur_init(&c, data, len);

        while (!c.err && c.pos < len) {
            uint32_t length = dwarf_u32(&c);
            if (c.err)
                return -1;

            /* 64-bit DWARF not supported */
            if (length == 0xffffffffu)
                return -1;

            /* terminator */
            if (length == 0)
                break;

            size_t entry_end = c.pos + length;
            if (entry_end > len)
                return -1;

            uint32_t id = dwarf_u32(&c);
            if (c.err)
                return -1;

            if (id != 0x00000000u) {
                /* FDE */
                nfde++;
            }

            c.pos = entry_end;
        }
        if (c.err)
            return -1;
    }

    if (nfde == 0)
        return 0;

    s->fdes = malloc(nfde * sizeof(*s->fdes));
    if (!s->fdes)
        return -1;

    /* Second pass: fill FDE table */
    size_t idx = 0;
    {
        struct dwarf_cur c;
        dwarf_cur_init(&c, data, len);

        while (!c.err && c.pos < len) {
            uint32_t length = dwarf_u32(&c);
            if (c.err)
                goto fail;

            if (length == 0xffffffffu || length == 0)
                break;

            size_t entry_end = c.pos + length;
            if (entry_end > len)
                goto fail;

            /* Record position of the id field (needed for cie_off calc) */
            uint32_t id_field_off = (uint32_t)c.pos;

            uint32_t id = dwarf_u32(&c);
            if (c.err)
                goto fail;

            if (id == 0x00000000u) {
                /* CIE — skip */
                c.pos = entry_end;
                continue;
            }

            /* FDE: cie_off = (offset of id field) - id */
            if (idx >= nfde)
                goto fail;

            /* Guard against underflow */
            if ((uint32_t)id_field_off < id)
                goto fail;
            uint32_t cie_off = id_field_off - id;

            /* Parse the governing CIE to get fde_enc */
            struct cfi_cie cie;
            if (parse_cie(data, len, cie_off, &cie) != 0)
                goto fail;

            /* Decode initial_location: pcrel from field's vaddr */
            uint64_t field_vaddr = section_vaddr + (uint64_t)c.pos;
            uint64_t pc_lo;
            if (decode_eh_pe(&c, cie.fde_enc, field_vaddr, 1, &pc_lo) != 0)
                goto fail;

            /* Decode address_range: FORMAT part only, no pcrel */
            uint64_t addr_range;
            if (decode_eh_pe(&c, cie.fde_enc, 0, 0, &addr_range) != 0)
                goto fail;

            if (c.err || c.pos > entry_end)
                goto fail;

            /* If the CIE augmentation starts with 'z', each FDE carries an
             * aug-data block (uleb length + bytes) to skip before the insns. */
            if (cie.has_z) {
                uint64_t fde_aug_len = dwarf_uleb(&c);
                if (c.err)
                    goto fail;
                if (c.pos + (size_t)fde_aug_len > entry_end)
                    goto fail;
                c.pos += (size_t)fde_aug_len;
            }

            struct cfi_fde *fde = &s->fdes[idx++];
            fde->pc_lo    = pc_lo;
            fde->pc_hi    = pc_lo + addr_range;
            fde->cie_off  = cie_off;
            fde->insn_off = (uint32_t)c.pos;
            fde->insn_len = (uint32_t)(entry_end - c.pos);

            c.pos = entry_end;
        }
        if (c.err)
            goto fail;
    }

    s->nfde = idx;
    qsort(s->fdes, s->nfde, sizeof(*s->fdes), fde_cmp);
    return 0;

fail:
    free(s->fdes);
    s->fdes = NULL;
    s->nfde = 0;
    return -1;
}

/* ---------------------------------------------------------------------------
 * Internal: parse the CIE at section offset cie_off from raw section bytes.
 * Shared by cfi_parse_debug_frame (FDE addr_size lookup) and cfi_read_cie
 * (public API).  Returns 0 on success, -1 on malformed.
 *
 * Auto-detects dialect from the id field at cie_off+4:
 *   id == 0x00000000  => .eh_frame CIE (version 1/3, "zR" augmentation)
 *   id == 0xffffffff  => .debug_frame CIE (existing behavior, unchanged)
 * -------------------------------------------------------------------------*/
static int parse_cie(const uint8_t *data, size_t len,
                     uint32_t cie_off, struct cfi_cie *out)
{
    if ((size_t)cie_off + 8 > len)
        return -1;

    struct dwarf_cur c;
    dwarf_cur_init(&c, data, len);
    c.pos = cie_off;

    /* length field */
    uint32_t length = dwarf_u32(&c);
    if (c.err)
        return -1;

    /* 64-bit DWARF sentinel — not supported */
    if (length == 0xffffffffu)
        return -1;

    /* zero-length == terminator, not a real CIE */
    if (length == 0)
        return -1;

    size_t entry_end = c.pos + length;
    if (entry_end > len)
        return -1;

    /* id: 0 => eh_frame CIE; 0xffffffff => debug_frame CIE; else not a CIE */
    uint32_t id = dwarf_u32(&c);
    if (c.err)
        return -1;

    int is_eh = (id == 0x00000000u);
    if (!is_eh && id != 0xffffffffu)
        return -1;

    uint8_t version = dwarf_u8(&c);
    if (c.err)
        return -1;

    /* Augmentation string: NUL-terminated.
     * For eh_frame we need to record each letter to decode aug-data later.
     * For debug_frame we reject 'z' (handled by the is_eh branch).
     * Collect up to 8 significant chars (plenty for "zRPL").             */
    char aug[8];
    int  naug = 0;
    while (!c.err && c.pos < entry_end) {
        uint8_t b = dwarf_u8(&c);
        if (c.err)
            return -1;
        if (b == 0)
            break;
        if (naug < (int)(sizeof(aug) - 1))
            aug[naug++] = (char)b;
    }
    aug[naug] = '\0';
    if (c.err)
        return -1;

    if (!is_eh) {
        /* debug_frame path: 'z' augmentation unsupported here */
        if (naug > 0 && aug[0] == 'z')
            return -1;
    }

    /* v4 introduces address_size and segment_selector_size (debug_frame only) */
    uint8_t addr_size = 8; /* default for v1/v3 on aarch64 */
    if (!is_eh && version == 4) {
        addr_size = dwarf_u8(&c);
        dwarf_u8(&c); /* segment_selector_size — skip */
        if (c.err)
            return -1;
    }

    uint64_t code_align = dwarf_uleb(&c);
    int64_t  data_align = dwarf_sleb(&c);
    if (c.err)
        return -1;

    /* ra_register: uleb always in eh_frame (v1 or v3); u8 for debug_frame v1 */
    uint32_t ra_reg;
    if (!is_eh && version == 1) {
        ra_reg = dwarf_u8(&c);
    } else {
        ra_reg = (uint32_t)dwarf_uleb(&c);
    }
    if (c.err)
        return -1;

    /* eh_frame: if aug starts with 'z', parse augmentation-data block */
    uint8_t fde_enc = 0xff; /* default: omit / DW_EH_PE_omit */
    uint8_t has_z = (is_eh && naug > 0 && aug[0] == 'z') ? 1 : 0;
    if (has_z) {
        uint64_t aug_len = dwarf_uleb(&c);
        if (c.err)
            return -1;
        size_t aug_end = c.pos + (size_t)aug_len;
        if (aug_end > entry_end)
            return -1;

        /* Walk the augmentation string (skip 'z' itself) and consume aug-data */
        for (int i = 1; i < naug && c.pos < aug_end; i++) {
            switch (aug[i]) {
            case 'R':
                /* next byte is the FDE pointer encoding */
                fde_enc = dwarf_u8(&c);
                if (c.err)
                    return -1;
                break;
            case 'P': {
                /* 1 encoding byte + 1 pointer encoded by that byte (skip both) */
                uint8_t penc = dwarf_u8(&c);
                if (c.err)
                    return -1;
                /* Determine pointer size from format nibble */
                uint8_t fmt = penc & 0x0fu;
                size_t psz;
                switch (fmt) {
                case 0x00: psz = 8; break; /* absptr = udata8 */
                case 0x02: psz = 2; break; /* udata2 */
                case 0x03: psz = 4; break; /* udata4 */
                case 0x04: psz = 8; break; /* udata8 */
                case 0x09: { /* sleb128 — scan for terminator */
                    while (c.pos < aug_end && !c.err) {
                        uint8_t b = dwarf_u8(&c);
                        if (c.err) return -1;
                        if (!(b & 0x80)) break;
                    }
                    psz = 0;
                    break;
                }
                case 0x0a: psz = 2; break; /* sdata2 */
                case 0x0b: psz = 4; break; /* sdata4 */
                case 0x0c: psz = 8; break; /* sdata8 */
                case 0x01: { /* uleb128 — scan for terminator */
                    while (c.pos < aug_end && !c.err) {
                        uint8_t b = dwarf_u8(&c);
                        if (c.err) return -1;
                        if (!(b & 0x80)) break;
                    }
                    psz = 0;
                    break;
                }
                default:
                    return -1;
                }
                if (psz > 0)
                    dwarf_skip(&c, psz);
                if (c.err)
                    return -1;
                break;
            }
            case 'L':
                /* 1 encoding byte — skip */
                dwarf_u8(&c);
                if (c.err)
                    return -1;
                break;
            default:
                /* unknown augmentation letter — skip remaining aug-data */
                c.pos = aug_end;
                break;
            }
        }

        /* Skip any remaining aug-data bytes */
        if (c.pos < aug_end)
            c.pos = aug_end;
    }

    /* remainder of the entry is initial_instructions */
    if (c.pos > entry_end)
        return -1;

    out->version    = version;
    out->addr_size  = addr_size;
    out->code_align = code_align;
    out->data_align = data_align;
    out->ra_reg     = ra_reg;
    out->fde_enc    = fde_enc;
    out->has_z      = has_z;
    out->insn_off   = (uint32_t)c.pos;
    out->insn_len   = (uint32_t)(entry_end - c.pos);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------*/

int cfi_read_cie(const struct cfi_section *s, uint32_t cie_off, struct cfi_cie *out)
{
    return parse_cie(s->data, s->len, cie_off, out);
}

static int fde_cmp(const void *a, const void *b)
{
    const struct cfi_fde *fa = (const struct cfi_fde *)a;
    const struct cfi_fde *fb = (const struct cfi_fde *)b;
    if (fa->pc_lo < fb->pc_lo) return -1;
    if (fa->pc_lo > fb->pc_lo) return  1;
    return 0;
}

int cfi_parse_debug_frame(struct cfi_section *s, const uint8_t *data, size_t len)
{
    s->data  = data;
    s->len   = len;
    s->fdes  = NULL;
    s->nfde  = 0;
    s->owned = NULL;          /* not heap-owned here; cfi_section_free frees this */
    s->section_vaddr = 0;     /* unused for .debug_frame (absolute addresses) */

    /* First pass: count FDEs so we can allocate exactly once. */
    size_t nfde = 0;
    {
        struct dwarf_cur c;
        dwarf_cur_init(&c, data, len);

        while (!c.err && c.pos < len) {
            uint32_t length = dwarf_u32(&c);
            if (c.err)
                return -1;

            /* 64-bit DWARF sentinel */
            if (length == 0xffffffffu)
                return -1;

            /* terminator */
            if (length == 0)
                break;

            size_t entry_end = c.pos + length;
            if (entry_end > len)
                return -1;

            uint32_t id = dwarf_u32(&c);
            if (c.err)
                return -1;

            if (id != 0xffffffffu) {
                /* It's an FDE */
                nfde++;
            }

            /* Jump to next entry */
            if (entry_end < c.pos)
                return -1;
            c.pos = entry_end;
        }
        if (c.err)
            return -1;
    }

    if (nfde == 0) {
        /* Empty section — valid, fdes stays NULL */
        return 0;
    }

    s->fdes = malloc(nfde * sizeof(*s->fdes));
    if (!s->fdes)
        return -1;

    /* Second pass: fill FDE table. */
    size_t idx = 0;
    {
        struct dwarf_cur c;
        dwarf_cur_init(&c, data, len);

        while (!c.err && c.pos < len) {
            uint32_t length = dwarf_u32(&c);
            if (c.err)
                goto fail;

            if (length == 0xffffffffu || length == 0)
                break;

            size_t entry_end = c.pos + length;
            if (entry_end > len)
                goto fail;

            uint32_t id = dwarf_u32(&c);
            if (c.err)
                goto fail;

            if (id == 0xffffffffu) {
                /* CIE — skip */
                c.pos = entry_end;
                continue;
            }

            /* FDE: id is the section offset of the governing CIE */
            if (idx >= nfde)
                goto fail; /* more FDEs than first pass counted — malformed */
            uint32_t cie_off = id;

            /* Look up the CIE to get addr_size */
            struct cfi_cie cie;
            if (parse_cie(data, len, cie_off, &cie) != 0)
                goto fail;

            uint8_t addr_size = cie.addr_size;

            /* Read initial_location and address_range */
            uint64_t pc_lo, addr_range;
            if (addr_size == 8) {
                pc_lo      = dwarf_u64(&c);
                addr_range = dwarf_u64(&c);
            } else if (addr_size == 4) {
                pc_lo      = dwarf_u32(&c);
                addr_range = dwarf_u32(&c);
            } else {
                goto fail;
            }
            if (c.err)
                goto fail;

            if (c.pos > entry_end)
                goto fail;

            struct cfi_fde *fde = &s->fdes[idx++];
            fde->pc_lo    = pc_lo;
            fde->pc_hi    = pc_lo + addr_range;
            fde->cie_off  = cie_off;
            fde->insn_off = (uint32_t)c.pos;
            fde->insn_len = (uint32_t)(entry_end - c.pos);

            c.pos = entry_end;
        }
        if (c.err)
            goto fail;
    }

    s->nfde = idx;
    qsort(s->fdes, s->nfde, sizeof(*s->fdes), fde_cmp);
    return 0;

fail:
    free(s->fdes);
    s->fdes = NULL;
    s->nfde = 0;
    return -1;
}

const struct cfi_fde *cfi_lookup(const struct cfi_section *s, uint64_t pc)
{
    if (!s->fdes || s->nfde == 0)
        return NULL;

    /* Binary search for the greatest pc_lo <= pc */
    size_t lo = 0, hi = s->nfde;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (s->fdes[mid].pc_lo <= pc)
            lo = mid;
        else
            hi = mid;
    }

    /* lo is the candidate — check pc_lo <= pc < pc_hi */
    const struct cfi_fde *f = &s->fdes[lo];
    if (f->pc_lo <= pc && pc < f->pc_hi)
        return f;
    return NULL;
}

void cfi_section_free(struct cfi_section *s)
{
    free(s->fdes);
    s->fdes = NULL;
    s->nfde = 0;
    free(s->owned);
    s->owned = NULL;
}

int cfi_load_elf(const uint8_t *elf, size_t len, struct cfi_section *out)
{
    memset(out, 0, sizeof(*out));

    const uint8_t *sec;
    size_t sec_len;
    uint64_t vaddr = 0;
    int is_eh;

    if (cfi_extract_eh_frame(elf, len, &sec, &sec_len, &vaddr) == 0) {
        is_eh = 1;
    } else if (cfi_extract_debug_frame(elf, len, &sec, &sec_len) == 0) {
        is_eh = 0;
        vaddr = 0;
    } else {
        return -1;
    }

    uint8_t *buf = malloc(sec_len);
    if (!buf)
        return -1;
    memcpy(buf, sec, sec_len);

    int r = is_eh ? cfi_parse_eh_frame(out, buf, sec_len, vaddr)
                  : cfi_parse_debug_frame(out, buf, sec_len);
    if (r != 0) {
        free(buf);
        /* parsers set fdes=NULL on failure; out->owned is still 0 from memset */
        return -1;
    }

    out->owned = buf;
    return 0;
}

/* ---------------------------------------------------------------------------
 * CFI program interpreter (Task 5)
 * -------------------------------------------------------------------------*/

#define CFI_REMEMBER_DEPTH 8

/* One saved state for remember_state/restore_state. */
struct cfi_saved_state {
    uint32_t        cfa_reg;
    int64_t         cfa_off;
    struct cfi_rule cols[CFI_NREG];
};

/*
 * Run one CFI instruction program (CIE or FDE) from [insn_off, insn_off+insn_len)
 * in the section, advancing *st up to (but not past) stop_loc.
 *
 * For CIE programs: pass stop_loc = UINT64_MAX (no advance_loc cutoff).
 * For FDE programs: pass stop_loc = module_pc; start_loc = fde->pc_lo.
 *
 * remember_stack / remember_depth: shared between CIE and FDE calls (pass
 * the same array; depth should be 0 at entry to CIE program).
 *
 * initial_cols: if non-NULL, DW_CFA_restore reads from it; must be set after
 * the CIE program completes. NULL disables restore (safe for CIE pass).
 *
 * Returns 0 on success, -1 on malformed/unsupported opcode.
 */
static int run_program(const struct cfi_section *s,
                       uint32_t insn_off, uint32_t insn_len,
                       uint64_t code_align, int64_t data_align,
                       uint64_t stop_loc, uint64_t start_loc,
                       struct cfi_cfa_state *st,
                       const struct cfi_rule *initial_cols,
                       struct cfi_saved_state *remember_stack,
                       int *remember_depth)
{
    struct dwarf_cur c;
    dwarf_cur_init(&c, s->data, s->len);
    c.pos = insn_off;

    size_t end = insn_off + insn_len;
    uint64_t loc = start_loc;

    while (!c.err && c.pos < end) {
        uint8_t op = dwarf_u8(&c);
        if (c.err)
            return -1;

        uint8_t high = op & 0xc0u;
        uint8_t low  = op & 0x3fu;

        if (high == 0x40u) {
            /* DW_CFA_advance_loc */
            uint64_t delta = (uint64_t)low * code_align;
            uint64_t newloc = loc + delta;
            if (newloc > stop_loc)
                return 0; /* row for stop_loc is current state */
            loc = newloc;
        } else if (high == 0x80u) {
            /* DW_CFA_offset: reg=low, N=uleb */
            uint64_t n = dwarf_uleb(&c);
            if (c.err) return -1;
            if (low < CFI_NREG) {
                st->cols[low].kind = CFI_AT_CFA;
                st->cols[low].off  = (int64_t)n * data_align;
            }
        } else if (high == 0xc0u) {
            /* DW_CFA_restore: reg=low */
            if (initial_cols && low < CFI_NREG)
                st->cols[low] = initial_cols[low];
        } else {
            /* Extended opcodes (high == 0x00) */
            switch (op) {
            case 0x00: /* DW_CFA_nop */
                break;

            case 0x02: { /* DW_CFA_advance_loc1 */
                uint8_t d = dwarf_u8(&c);
                if (c.err) return -1;
                uint64_t newloc = loc + (uint64_t)d * code_align;
                if (newloc > stop_loc) return 0;
                loc = newloc;
                break;
            }
            case 0x03: { /* DW_CFA_advance_loc2 */
                uint16_t d = dwarf_u16(&c);
                if (c.err) return -1;
                uint64_t newloc = loc + (uint64_t)d * code_align;
                if (newloc > stop_loc) return 0;
                loc = newloc;
                break;
            }
            case 0x04: { /* DW_CFA_advance_loc4 */
                uint32_t d = dwarf_u32(&c);
                if (c.err) return -1;
                uint64_t newloc = loc + (uint64_t)d * code_align;
                if (newloc > stop_loc) return 0;
                loc = newloc;
                break;
            }

            case 0x05: { /* DW_CFA_offset_extended */
                uint64_t reg = dwarf_uleb(&c);
                uint64_t n   = dwarf_uleb(&c);
                if (c.err) return -1;
                if (reg < CFI_NREG) {
                    st->cols[reg].kind = CFI_AT_CFA;
                    st->cols[reg].off  = (int64_t)n * data_align;
                }
                break;
            }
            case 0x06: { /* DW_CFA_restore_extended */
                uint64_t reg = dwarf_uleb(&c);
                if (c.err) return -1;
                if (initial_cols && reg < CFI_NREG)
                    st->cols[reg] = initial_cols[reg];
                break;
            }
            case 0x07: { /* DW_CFA_undefined */
                uint64_t reg = dwarf_uleb(&c);
                if (c.err) return -1;
                if (reg < CFI_NREG) {
                    st->cols[reg].kind = CFI_UNDEF;
                    st->cols[reg].off  = 0;
                }
                break;
            }
            case 0x08: { /* DW_CFA_same_value */
                uint64_t reg = dwarf_uleb(&c);
                if (c.err) return -1;
                if (reg < CFI_NREG) {
                    st->cols[reg].kind = CFI_SAME;
                    st->cols[reg].off  = 0;
                }
                break;
            }
            case 0x09: /* DW_CFA_register — not supported */
                return -1;

            case 0x0a: { /* DW_CFA_remember_state */
                if (*remember_depth >= CFI_REMEMBER_DEPTH)
                    return -1;
                struct cfi_saved_state *slot = &remember_stack[(*remember_depth)++];
                slot->cfa_reg = st->cfa_reg;
                slot->cfa_off = st->cfa_off;
                for (int i = 0; i < CFI_NREG; i++)
                    slot->cols[i] = st->cols[i];
                break;
            }
            case 0x0b: { /* DW_CFA_restore_state */
                if (*remember_depth <= 0)
                    return -1;
                struct cfi_saved_state *slot = &remember_stack[--(*remember_depth)];
                st->cfa_reg = slot->cfa_reg;
                st->cfa_off = slot->cfa_off;
                for (int i = 0; i < CFI_NREG; i++)
                    st->cols[i] = slot->cols[i];
                break;
            }

            case 0x0c: { /* DW_CFA_def_cfa: reg=uleb, off=uleb (NOT factored) */
                uint64_t reg = dwarf_uleb(&c);
                uint64_t off = dwarf_uleb(&c);
                if (c.err) return -1;
                st->cfa_reg = (uint32_t)reg;
                st->cfa_off = (int64_t)off;
                break;
            }
            case 0x0d: { /* DW_CFA_def_cfa_register: cfa_reg=uleb, keep cfa_off */
                uint64_t reg = dwarf_uleb(&c);
                if (c.err) return -1;
                st->cfa_reg = (uint32_t)reg;
                break;
            }
            case 0x0e: { /* DW_CFA_def_cfa_offset: cfa_off=uleb (NOT factored), keep cfa_reg */
                uint64_t off = dwarf_uleb(&c);
                if (c.err) return -1;
                st->cfa_off = (int64_t)off;
                break;
            }

            default:
                return -1; /* unknown extended opcode */
            }
        }
    }

    if (c.err)
        return -1;
    return 0;
}

int cfi_run_program(const struct cfi_section *s, uint64_t module_pc,
                    struct cfi_cfa_state *out)
{
    const struct cfi_fde *fde = cfi_lookup(s, module_pc);
    if (!fde)
        return -1;

    struct cfi_cie cie;
    if (cfi_read_cie(s, fde->cie_off, &cie) != 0)
        return -1;

    /* Initialize state: CFA undefined, all cols UNDEF */
    struct cfi_cfa_state st;
    st.cfa_reg = 0;
    st.cfa_off = 0;
    for (int i = 0; i < CFI_NREG; i++) {
        st.cols[i].kind = CFI_UNDEF;
        st.cols[i].off  = 0;
    }
    /* The return-address register defaults to "same value": until a function
     * spills its link register, the caller's return address is still live in the
     * RA register (x30 on aarch64). Leaf frames — e.g. libc syscall stubs like
     * __openat, and the art_jni_trampoline stub — emit no RA rule, so without this
     * default they would be read as top-of-stack and the unwind would stop at the
     * first frame. Any explicit CIE/FDE rule below overrides this. */
    if (cie.ra_reg < CFI_NREG)
        st.cols[cie.ra_reg].kind = CFI_SAME;

    struct cfi_saved_state remember_stack[CFI_REMEMBER_DEPTH];
    int remember_depth = 0;

    /* Run CIE initial instructions (no PC cutoff) */
    if (run_program(s, cie.insn_off, cie.insn_len,
                    cie.code_align, cie.data_align,
                    UINT64_MAX, 0,
                    &st, NULL, remember_stack, &remember_depth) != 0)
        return -1;

    /* Snapshot initial_cols for DW_CFA_restore */
    struct cfi_rule initial_cols[CFI_NREG];
    for (int i = 0; i < CFI_NREG; i++)
        initial_cols[i] = st.cols[i];

    /* Run FDE instructions up to module_pc */
    if (run_program(s, fde->insn_off, fde->insn_len,
                    cie.code_align, cie.data_align,
                    module_pc, fde->pc_lo,
                    &st, initial_cols, remember_stack, &remember_depth) != 0)
        return -1;

    *out = st;
    return 0;
}

int cfi_step(const struct cfi_section *s, uint64_t module_pc,
             uint64_t x[CFI_NREG], uint64_t *sp, uint64_t *pc,
             const uint8_t *stack, uint64_t stack_base, size_t stack_len)
{
    struct cfi_cfa_state st;
    if (cfi_run_program(s, module_pc, &st) != 0)
        return 0;

    /* Compute CFA = regval(cfa_reg) + cfa_off */
    uint64_t cfa;
    if (st.cfa_reg == CFI_REG_SP)
        cfa = *sp + (uint64_t)(int64_t)st.cfa_off;
    else if (st.cfa_reg < CFI_NREG)
        cfa = x[st.cfa_reg] + (uint64_t)(int64_t)st.cfa_off;
    else
        return 0; /* unknown CFA register */

    /* Bounds-checked 8-byte little-endian read from frozen stack window */
#define read64(addr, valp) \
    ((addr) >= stack_base && (addr) + 8 <= stack_base + stack_len \
     ? (*(valp) = \
            (uint64_t)stack[(addr)-stack_base]         | \
            ((uint64_t)stack[(addr)-stack_base+1] << 8)  | \
            ((uint64_t)stack[(addr)-stack_base+2] << 16) | \
            ((uint64_t)stack[(addr)-stack_base+3] << 24) | \
            ((uint64_t)stack[(addr)-stack_base+4] << 32) | \
            ((uint64_t)stack[(addr)-stack_base+5] << 40) | \
            ((uint64_t)stack[(addr)-stack_base+6] << 48) | \
            ((uint64_t)stack[(addr)-stack_base+7] << 56), 1) \
     : 0)

    /* Resolve RA = column 30 */
    uint32_t ra_reg = 30; /* AArch64 LR */
    uint64_t caller_pc = 0;
    struct cfi_rule *ra_rule = &st.cols[ra_reg];
    if (ra_rule->kind == CFI_AT_CFA) {
        uint64_t slot = (uint64_t)(int64_t)(cfa + (uint64_t)(int64_t)ra_rule->off);
        if (!read64(slot, &caller_pc))
            return 0;
    } else if (ra_rule->kind == CFI_SAME) {
        caller_pc = x[ra_reg];
    } else {
        /* CFI_UNDEF: top of stack */
        return 0;
    }

    if (caller_pc == 0)
        return 0;

    /* Restore registers: work on a copy, commit only on success */
    uint64_t newx[CFI_NREG];
    for (int i = 0; i < CFI_NREG; i++)
        newx[i] = x[i];

    for (int r = 0; r < CFI_NREG; r++) {
        if (st.cols[r].kind == CFI_AT_CFA) {
            uint64_t slot = (uint64_t)(int64_t)(cfa + (uint64_t)(int64_t)st.cols[r].off);
            uint64_t val;
            if (read64(slot, &val))
                newx[r] = val;
            /* on read failure, leave unchanged (only RA failure stops unwind) */
        }
        /* CFI_SAME / CFI_UNDEF: leave newx[r] = x[r] */
    }

#undef read64

    /* Commit */
    for (int i = 0; i < CFI_NREG; i++)
        x[i] = newx[i];
    *sp = cfa;
    *pc = caller_pc;
    return 1;
}
