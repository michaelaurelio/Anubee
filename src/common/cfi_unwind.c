#include "common/cfi_unwind.h"
#include "common/dwarf.h"

#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Internal: parse the CIE at section offset cie_off from raw section bytes.
 * Shared by cfi_parse_debug_frame (FDE addr_size lookup) and cfi_read_cie
 * (public API).  Returns 0 on success, -1 on malformed.
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

    /* id must be 0xffffffff (CIE marker) */
    uint32_t id = dwarf_u32(&c);
    if (c.err || id != 0xffffffffu)
        return -1;

    uint8_t version = dwarf_u8(&c);
    if (c.err)
        return -1;

    /* augmentation: NUL-terminated string */
    uint8_t aug0 = 0;
    while (!c.err && c.pos < entry_end) {
        uint8_t b = dwarf_u8(&c);
        if (c.err)
            return -1;
        if (aug0 == 0)
            aug0 = b;   /* save first char for 'z' check */
        if (b == 0)
            break;      /* consumed NUL terminator */
    }
    if (c.err)
        return -1;

    /* 'z' augmentation means .eh_frame pointer-encoding — not this task */
    if (aug0 == 'z')
        return -1;

    /* v4 introduces address_size and segment_selector_size */
    uint8_t addr_size = 8; /* default for v1/v3 on aarch64 */
    if (version == 4) {
        addr_size = dwarf_u8(&c);
        dwarf_u8(&c); /* segment_selector_size — skip */
        if (c.err)
            return -1;
    }

    uint64_t code_align = dwarf_uleb(&c);
    int64_t  data_align = dwarf_sleb(&c);
    if (c.err)
        return -1;

    /* ra_register: u8 for v1, uleb for v3/v4 */
    uint32_t ra_reg;
    if (version == 1) {
        ra_reg = dwarf_u8(&c);
    } else {
        ra_reg = (uint32_t)dwarf_uleb(&c);
    }
    if (c.err)
        return -1;

    /* remainder of the entry is initial_instructions */
    if (c.pos > entry_end)
        return -1;

    out->version    = version;
    out->addr_size  = addr_size;
    out->code_align = code_align;
    out->data_align = data_align;
    out->ra_reg     = ra_reg;
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
}
