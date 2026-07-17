// SPDX-License-Identifier: GPL-2.0
// anubee_coverage_report: emit a per-engine coverage-health record on two channels
// (stderr banner + JSON sink line). Pure C over struct anubee_coverage - no libbpf,
// host-testable.
#include "common/coverage.h"
#include "common/emit.h"
#include <stdio.h>

// cfi_stop_reason -> short JSON key. Index by enum value; keep in lockstep with
// cfi_unwind.h. CFI_OK and CFI_SNAP_PC_ZERO are clean terminals (see is_blind).
static const char *const k_stop_name[ANUBEE_CFI_STOP_N] = {
	[CFI_OK]                 = "ok",
	[CFI_NO_FDE]             = "no_fde",
	[CFI_RA_READFAULT]       = "ra_readfault",
	[CFI_BAD_CFA_REG]        = "bad_cfa_reg",
	[CFI_RA_UNDEF]           = "ra_undef",
	[CFI_RA_ZERO]            = "ra_zero",
	[CFI_RUN_FAIL]           = "run_fail",
	[CFI_SNAP_PC_ZERO]       = "snap_pc_zero",
	[CFI_SNAP_NO_MAPPING]    = "snap_no_mapping",
	[CFI_SNAP_CFI_GET_NULL]  = "snap_cfi_get_null",
};
_Static_assert(ANUBEE_CFI_STOP_N == 10,
	"cfi_stop_reason changed - update k_stop_name and this assert");

const char *anubee_cfi_stop_name(int reason)
{
	if (reason < 0 || reason >= ANUBEE_CFI_STOP_N || !k_stop_name[reason])
		return "unknown";
	return k_stop_name[reason];
}

// True if the record carries any degradation signal at all.
static int cov_degraded(const struct anubee_coverage *c)
{
	if (c->snaps_truncated || c->ring_drops || c->queue_drops ||
	    c->managed_naming_off || c->prearm_drops || c->depth_capped ||
	    c->decode_partial)
		return 1;
	if (c->returns_mode && c->returns_captured < c->spans_opened)
		return 1;
	for (int i = 0; i < ANUBEE_CFI_STOP_N; i++)
		if (c->cfi_stop[i] && anubee_cfi_stop_is_blind(i))
			return 1;
	return 0;
}

// ---- JSON line into the sink's jbuf ----
static void cov_build_json(struct jbuf *j, const struct anubee_coverage *c, int degraded)
{
	jb_s(j, "{\"type\":\"coverage\",\"engine\":\"");
	jb_esc(j, c->engine ? c->engine : "?");
	jb_c(j, '"');
	if (!degraded) {
		jb_s(j, ",\"clean\":true");
		if (c->returns_mode) {
			jb_s(j, ",\"returns\":{\"spans\":"); jb_u64(j, c->spans_opened);
			jb_s(j, ",\"captured\":"); jb_u64(j, c->returns_captured); jb_c(j, '}');
		}
		jb_s(j, "}\n");
		return;
	}
	if (c->snaps_total || c->snaps_truncated) {
		jb_s(j, ",\"snaps\":{\"total\":"); jb_u64(j, c->snaps_total);
		jb_s(j, ",\"truncated\":"); jb_u64(j, c->snaps_truncated); jb_c(j, '}');
	}
	if (c->cfi_walks) {
		jb_s(j, ",\"cfi\":{\"walks\":"); jb_u64(j, c->cfi_walks);
		jb_s(j, ",\"stops\":{");
		int first = 1;
		for (int i = 0; i < ANUBEE_CFI_STOP_N; i++) {
			if (!c->cfi_stop[i] || !anubee_cfi_stop_is_blind(i)) continue;
			if (!first) jb_c(j, ',');
			first = 0;
			jb_c(j, '"'); jb_s(j, anubee_cfi_stop_name(i)); jb_s(j, "\":");
			jb_u64(j, c->cfi_stop[i]);
		}
		jb_s(j, "}}");
	}
	if (c->ring_drops || c->queue_drops) {
		jb_s(j, ",\"drops\":{\"ring\":"); jb_u64(j, c->ring_drops);
		jb_s(j, ",\"queue\":"); jb_u64(j, c->queue_drops); jb_c(j, '}');
	}
	if (c->managed_naming_off) jb_s(j, ",\"managed_naming_off\":true");
	if (c->prearm_drops) { jb_s(j, ",\"prearm_drops\":"); jb_u64(j, c->prearm_drops); }
	if (c->depth_capped) { jb_s(j, ",\"depth_capped\":"); jb_u64(j, c->depth_capped); }
	if (c->decode_partial) jb_s(j, ",\"decode_partial\":true");
	if (c->returns_mode) {
		jb_s(j, ",\"returns\":{\"spans\":"); jb_u64(j, c->spans_opened);
		jb_s(j, ",\"captured\":"); jb_u64(j, c->returns_captured); jb_c(j, '}');
	}
	jb_s(j, "}\n");
}

// ---- stderr banner ----
static void cov_banner(const struct anubee_coverage *c, int degraded)
{
	fprintf(stderr, "[coverage] %s: ", c->engine ? c->engine : "?");
	if (!degraded) {
		fprintf(stderr, "full coverage - no truncation, drops, or blind spots\n");
		return;
	}
	int n = 0;
	#define SEP() do { if (n++) fprintf(stderr, "; "); } while (0)
	if (c->snaps_truncated) { SEP();
		fprintf(stderr, "%llu/%llu snapshots truncated (stack >32KB)",
			c->snaps_truncated, c->snaps_total); }
	int anystop = 0;
	for (int i = 0; i < ANUBEE_CFI_STOP_N; i++)
		if (c->cfi_stop[i] && anubee_cfi_stop_is_blind(i)) anystop = 1;
	if (anystop) { SEP(); fprintf(stderr, "CFI stops:");
		int f = 1;
		for (int i = 0; i < ANUBEE_CFI_STOP_N; i++) {
			if (!c->cfi_stop[i] || !anubee_cfi_stop_is_blind(i)) continue;
			fprintf(stderr, "%s %llu %s", f ? "" : ",", c->cfi_stop[i],
				anubee_cfi_stop_name(i));
			f = 0;
		}
	}
	if (c->ring_drops || c->queue_drops) { SEP();
		fprintf(stderr, "%llu ring drops", c->ring_drops);
		if (c->queue_drops) fprintf(stderr, ", %llu queue drops", c->queue_drops); }
	if (c->managed_naming_off) { SEP(); fprintf(stderr, "Java naming OFF (unknown ART build)"); }
	if (c->prearm_drops) { SEP(); fprintf(stderr, "%llu syscalls dropped (pre-arm window)", c->prearm_drops); }
	if (c->depth_capped) { SEP(); fprintf(stderr, "%llu stack depth-capped", c->depth_capped); }
	if (c->decode_partial) { SEP(); fprintf(stderr, "syscall args not decoded (raw)"); }
	if (c->returns_mode && c->returns_captured < c->spans_opened) { SEP();
		fprintf(stderr, "%llu/%llu function returns captured (%llu missed; "
			"SP-reconcile backstop or ring drop)", c->returns_captured, c->spans_opened,
			c->spans_opened - c->returns_captured); }
	#undef SEP
	fprintf(stderr, "\n");
}

void anubee_coverage_report(struct anubee_sink *sink, const struct anubee_coverage *cov)
{
	// SYM1 Phase 5b: exempt is a distinct record shape, not a variant of
	// "clean" -- an engine with no coverage surface (lib/dump) says so
	// explicitly instead of either staying silent or misrendering as
	// "full coverage" (which would falsely imply signals were checked).
	if (cov->exempt) {
		const char *reason = cov->exempt_reason ? cov->exempt_reason : "no coverage surface";
		fprintf(stderr, "[coverage] %s: not applicable (%s)\n",
			cov->engine ? cov->engine : "?", reason);
		if (sink && sink->f) {
			struct jbuf *j = &sink->jb;
			j->len = 0;
			jb_s(j, "{\"type\":\"coverage\",\"engine\":\"");
			jb_esc(j, cov->engine ? cov->engine : "?");
			jb_s(j, "\",\"exempt\":true,\"reason\":\"");
			jb_esc(j, reason);
			jb_s(j, "\"}\n");
			anubee_sink_emit(sink);
		}
		return;
	}
	int degraded = cov_degraded(cov);
	cov_banner(cov, degraded);
	if (sink && sink->f) {          // JSON line only when -o is active
		cov_build_json(&sink->jb, cov, degraded);
		anubee_sink_emit(sink);
	}
}
