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
