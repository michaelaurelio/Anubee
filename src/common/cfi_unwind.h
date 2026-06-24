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

#endif
