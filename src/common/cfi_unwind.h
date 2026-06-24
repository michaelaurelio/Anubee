#ifndef ARES_CFI_UNWIND_H
#define ARES_CFI_UNWIND_H
#include <stdint.h>
#include <stddef.h>

struct cfi_cie {
	uint8_t  version;
	uint8_t  addr_size;     /* bytes per address (8 on aarch64) */
	uint64_t code_align;    /* code_alignment_factor (uleb) */
	int64_t  data_align;    /* data_alignment_factor (sleb) */
	uint32_t ra_reg;        /* return_address_register (30 = LR on aarch64) */
	uint32_t insn_off;      /* section offset of CIE initial_instructions */
	uint32_t insn_len;      /* length of initial_instructions */
};

struct cfi_fde {
	uint64_t pc_lo, pc_hi;  /* [pc_lo, pc_hi) module-relative range this FDE covers */
	uint32_t cie_off;       /* section offset of the governing CIE */
	uint32_t insn_off;      /* section offset of FDE instructions */
	uint32_t insn_len;      /* length of FDE instructions */
};

struct cfi_section {
	const uint8_t *data;    /* borrowed section bytes; caller keeps alive for the section's life */
	size_t         len;
	struct cfi_fde *fdes;   /* malloc'd, sorted ascending by pc_lo */
	size_t         nfde;
};

/* Parse a .debug_frame section. Returns 0 on success (fills s->fdes/nfde), -1 on a malformed
 * section. `data` is borrowed (not copied) and must outlive the section. */
int  cfi_parse_debug_frame(struct cfi_section *s, const uint8_t *data, size_t len);

/* Parse the CIE at section offset cie_off into *out. Returns 0 on success, -1 on malformed. */
int  cfi_read_cie(const struct cfi_section *s, uint32_t cie_off, struct cfi_cie *out);

/* Return the FDE whose [pc_lo,pc_hi) contains pc (module-relative), or NULL. O(log n). */
const struct cfi_fde *cfi_lookup(const struct cfi_section *s, uint64_t pc);

/* Free s->fdes (does NOT free the borrowed data buffer). */
void cfi_section_free(struct cfi_section *s);

/* ---- CFI interpreter types (Task 5) -------------------------------------- */

/* A register's recovery rule for a given PC row. */
struct cfi_rule {
	uint8_t kind;     /* CFI_UNDEF=0, CFI_SAME=1, CFI_AT_CFA=2 (saved at CFA + off) */
	int64_t off;      /* byte offset from CFA when kind==CFI_AT_CFA */
};
enum { CFI_UNDEF = 0, CFI_SAME = 1, CFI_AT_CFA = 2 };

#define CFI_NREG 31       /* x0..x30 */
#define CFI_REG_SP 31     /* DWARF reg 31 = sp on aarch64 */

/* CFA + per-register rules at one PC row. CFA = regval(cfa_reg) + cfa_off,
 * where regval(31)=sp, regval(r)=x[r] otherwise. */
struct cfi_cfa_state {
	uint32_t cfa_reg;
	int64_t  cfa_off;
	struct cfi_rule cols[CFI_NREG];
};

/* Interpret the CIE initial instructions then the FDE instructions, accumulating rules up to
 * (and including) module_pc. Fills *out. Returns 0 on success, -1 if no FDE covers module_pc
 * or the program is malformed. module_pc is in the section's address space (caller maps a
 * runtime PC to module-relative first). */
int cfi_run_program(const struct cfi_section *s, uint64_t module_pc, struct cfi_cfa_state *out);

/* Step one frame up. On entry x[0..30], *sp, *pc describe the current frame; module_pc is *pc
 * mapped to this section's space. Computes CFA and the caller's registers by reading the frozen
 * stack window [stack_base, stack_base+stack_len), and overwrites x[], *sp, *pc with the caller
 * frame. Returns 1 if a caller frame was recovered, 0 to STOP the unwind (no FDE, RA undefined,
 * caller PC == 0, or a needed stack slot lies outside the window). Never reads outside the window. */
int cfi_step(const struct cfi_section *s, uint64_t module_pc,
	     uint64_t x[CFI_NREG], uint64_t *sp, uint64_t *pc,
	     const uint8_t *stack, uint64_t stack_base, size_t stack_len);

#endif
