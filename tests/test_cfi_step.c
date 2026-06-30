/* tests/test_cfi_step.c */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "common/cfi_unwind.h"

static const uint8_t DF5[] = {
    0x14, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x04, 0x00, 0x08, 0x00, 0x01, 0x7c, 0x1e,
    0x0c, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0c, 0x1d, 0x10, 0x9d, 0x04, 0x9e, 0x02, 0x00
};

/* Same CIE as DF5 (CFA=sp+0, RA=reg30, data_align=-4). One FDE over [0x100,0x200)
 * whose program is: def_cfa x29,16; offset x29,-16; offset x30,-8;
 * DW_CFA_AARCH64_negate_ra_state (0x2d); nop.  FDE body = 29 bytes (len 0x1d). */
static const uint8_t DF_PAC1[] = {
    0x14,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0x04,0x00,0x08,0x00, 0x01,0x7c,0x1e,
    0x0c,0x1f,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,
    0x1d,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x0c,0x1d,0x10, 0x9d,0x04, 0x9e,0x02, 0x2d, 0x00
};

/* Same CIE. FDE program: def_cfa x29,16; negate(ra_signed=1); remember;
 * negate(ra_signed=0); restore(-> ra_signed=1); offset x30,-8; nop.
 * FDE body = 30 bytes (len 0x1e). Proves ra_signed survives remember/restore. */
static const uint8_t DF_PAC2[] = {
    0x14,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0x04,0x00,0x08,0x00, 0x01,0x7c,0x1e,
    0x0c,0x1f,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,
    0x1e,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x0c,0x1d,0x10, 0x2d, 0x0a, 0x2d, 0x0b, 0x9e,0x02, 0x00
};

static void st64(uint8_t *buf, uint64_t v) { for (int i=0;i<8;i++) buf[i]=(uint8_t)(v>>(8*i)); }

int main(void)
{
	struct cfi_section s;
	assert(cfi_parse_debug_frame(&s, DF5, sizeof(DF5)) == 0 && s.nfde == 1);

	/* run_program at pc 0x140: CFA = x29 + 16; x29 saved at CFA-16; RA(x30) at CFA-8 */
	struct cfi_cfa_state st;
	assert(cfi_run_program(&s, 0x140, &st) == 0);
	assert(st.cfa_reg == 29 && st.cfa_off == 16);
	assert(st.cols[29].kind == CFI_AT_CFA && st.cols[29].off == -16);
	assert(st.cols[30].kind == CFI_AT_CFA && st.cols[30].off == -8);

	/* Build a frozen stack window [0x8000, 0x8040). x29=0x8010 -> CFA=0x8020.
	 * caller x29 at 0x8010, caller pc (RA) at 0x8018. */
	uint8_t stack[0x40]; memset(stack, 0, sizeof(stack));
	st64(&stack[0x10], 0xAAAA0000BBBB1111ull);   /* addr 0x8010 = caller x29 */
	st64(&stack[0x18], 0x0000000001234560ull);   /* addr 0x8018 = caller pc/RA */

	uint64_t x[31]; memset(x, 0, sizeof(x));
	x[29] = 0x8010;
	uint64_t sp = 0x8000, pc = 0x140;

	int r = cfi_step(&s, 0x140, x, &sp, &pc, stack, 0x8000, sizeof(stack), NULL);
	assert(r == 1);
	assert(pc == 0x0000000001234560ull);   /* caller PC from RA */
	assert(sp == 0x8020);                   /* caller SP = CFA */
	assert(x[29] == 0xAAAA0000BBBB1111ull); /* caller x29 restored */
	assert(x[30] == 0x0000000001234560ull); /* caller x30 == RA */

	/* RA slot outside the window -> stop (return 0), no OOB read */
	uint64_t x2[31]; memset(x2,0,sizeof(x2)); x2[29]=0x9000;  /* CFA=0x9010, far outside window */
	uint64_t sp2=0x8000, pc2=0x140;
	assert(cfi_step(&s, 0x140, x2, &sp2, &pc2, stack, 0x8000, sizeof(stack), NULL) == 0);

	/* pc with no FDE -> stop */
	uint64_t x3[31]; memset(x3,0,sizeof(x3));
	uint64_t sp3=0, pc3=0x9999;
	assert(cfi_step(&s, 0x9999, x3, &sp3, &pc3, stack, 0x8000, sizeof(stack), NULL) == 0);

	/* Diagnostics: no-FDE PC reports CFI_NO_FDE + fde_found=0. */
	struct cfi_step_diag d_nofde; memset(&d_nofde, 0, sizeof(d_nofde));
	uint64_t xd[31]; memset(xd,0,sizeof(xd)); uint64_t spd=0, pcd=0x9999;
	assert(cfi_step(&s, 0x9999, xd, &spd, &pcd, stack, 0x8000, sizeof(stack), &d_nofde) == 0);
	assert(d_nofde.fde_found == 0);
	assert(d_nofde.stop_reason == CFI_NO_FDE);

	/* Diagnostics: RA slot outside the window reports CFI_RA_READFAULT and
	 * still finds the FDE (so this is a read fault, not a lookup miss). */
	struct cfi_step_diag d_fault; memset(&d_fault, 0, sizeof(d_fault));
	uint64_t xf[31]; memset(xf,0,sizeof(xf)); xf[29]=0x9000;
	uint64_t spf=0x8000, pcf=0x140;
	assert(cfi_step(&s, 0x140, xf, &spf, &pcf, stack, 0x8000, sizeof(stack), &d_fault) == 0);
	assert(d_fault.fde_found == 1);
	assert(d_fault.fde_pc_lo <= 0x140 && 0x140 < d_fault.fde_pc_hi);
	assert(d_fault.stop_reason == CFI_RA_READFAULT);
	assert(d_fault.ra_slot == 0x9008);  /* CFA(0x9010) + ra_off(-8) */

	/* Diagnostics: a successful step reports CFI_OK and the produced RA. */
	struct cfi_step_diag d_ok; memset(&d_ok, 0, sizeof(d_ok));
	uint64_t xo[31]; memset(xo,0,sizeof(xo)); xo[29]=0x8010;
	uint64_t spo=0x8000, pco=0x140;
	assert(cfi_step(&s, 0x140, xo, &spo, &pco, stack, 0x8000, sizeof(stack), &d_ok) == 1);
	assert(d_ok.stop_reason == CFI_OK);
	assert(d_ok.ra_value == 0x0000000001234560ull);
	assert(d_ok.cfa == 0x8020);

	cfi_section_free(&s);

	/* ares_pac_strip: clears PAC bits above the 48-bit user VA; no-op when clear. */
	assert(ares_pac_strip(0x0000007405ccb054ull) == 0x0000007405ccb054ull); /* unsigned -> unchanged */
	assert(ares_pac_strip(0x00bd007405ccb054ull) == 0x0000007405ccb054ull); /* signed   -> stripped  */
	assert(ares_pac_strip(0xffff007405ccb054ull) == 0x0000007405ccb054ull); /* all high -> stripped  */

	/* 0x2d no longer aborts the program; CFA/cols intact; ra_signed tracked. */
	{
		struct cfi_section sp1;
		assert(cfi_parse_debug_frame(&sp1, DF_PAC1, sizeof(DF_PAC1)) == 0 && sp1.nfde == 1);
		struct cfi_cfa_state stp1;
		assert(cfi_run_program(&sp1, 0x140, &stp1) == 0);          /* was -1 before the fix */
		assert(stp1.cfa_reg == 29 && stp1.cfa_off == 16);
		assert(stp1.cols[29].kind == CFI_AT_CFA && stp1.cols[29].off == -16);
		assert(stp1.cols[30].kind == CFI_AT_CFA && stp1.cols[30].off == -8);
		assert(stp1.ra_signed == 1);
		cfi_section_free(&sp1);
	}

	/* ra_signed survives remember_state/restore_state. */
	{
		struct cfi_section sp2;
		assert(cfi_parse_debug_frame(&sp2, DF_PAC2, sizeof(DF_PAC2)) == 0 && sp2.nfde == 1);
		struct cfi_cfa_state stp2;
		assert(cfi_run_program(&sp2, 0x140, &stp2) == 0);
		assert(stp2.ra_signed == 1);                                /* negate, remember, negate, restore -> 1 */
		assert(stp2.cols[30].kind == CFI_AT_CFA && stp2.cols[30].off == -8);
		cfi_section_free(&sp2);
	}

	/* cfi_step strips PAC bits from the RA when the row is ra_signed.
	 * DF_PAC1: CFA=x29+16, x29@CFA-16, x30(RA)@CFA-8, ra_signed=1.
	 * x29=0x8010 -> CFA=0x8020 -> RA slot 0x8018. Put a signed PC there. */
	{
		struct cfi_section psec;
		assert(cfi_parse_debug_frame(&psec, DF_PAC1, sizeof(DF_PAC1)) == 0 && psec.nfde == 1);
		uint8_t pstk[0x40]; memset(pstk, 0, sizeof(pstk));
		st64(&pstk[0x10], 0x0000000000008030ull);   /* 0x8010 = caller x29 */
		st64(&pstk[0x18], 0x00bd000001234560ull);   /* 0x8018 = caller pc/RA, PAC-signed */

		uint64_t xp[31]; memset(xp, 0, sizeof(xp)); xp[29] = 0x8010;
		uint64_t spp = 0x8000, pcp = 0x140;
		struct cfi_step_diag dp; memset(&dp, 0, sizeof(dp));
		int rp = cfi_step(&psec, 0x140, xp, &spp, &pcp, pstk, 0x8000, sizeof(pstk), &dp);
		assert(rp == 1);
		assert(pcp == 0x0000000001234560ull);   /* PAC bits 0x00bd.. masked off */
		assert(dp.ra_signed == 1);
		assert(dp.ra_value == 0x0000000001234560ull);  /* diag reports the stripped PC */
		cfi_section_free(&psec);
	}

	return 0;
}
