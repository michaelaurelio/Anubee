// Host unit tests for ares_coverage_report (CR5). Pure struct -> output.
#include "common/coverage.h"
#include "common/emit.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int checks = 0;
#define CHECK(c) do { assert(c); checks++; } while (0)

// Emit one coverage record to a temp -o sink, return the JSON line in out.
static void emit_json(const struct ares_coverage *cov, char *out, size_t n)
{
	char path[] = "/tmp/ares_cov_XXXXXX";
	int fd = mkstemp(path); assert(fd >= 0); close(fd);
	struct ares_sink s = {0};
	assert(ares_sink_open(&s, path, "coverage", /*jsonl=*/1) == 0);
	ares_coverage_report(&s, cov);
	ares_sink_close(&s);
	FILE *f = fopen(path, "r"); assert(f);
	out[0] = 0;
	char line[4096];
	while (fgets(line, sizeof(line), f))
		if (strstr(line, "\"type\":\"coverage\""))
			snprintf(out, n, "%s", line);
	fclose(f); remove(path);
}

int main(void)
{
	char j[4096];

	// 1. A degraded syscalls run: fields present, engine tagged.
	struct ares_coverage cov = {0};
	cov.engine = "syscalls";
	cov.snaps_total = 50; cov.snaps_truncated = 3;
	cov.cfi_walks = 201;
	cov.cfi_stop[CFI_NO_FDE] = 12;
	cov.cfi_stop[CFI_RA_READFAULT] = 2;
	cov.cfi_stop[CFI_SNAP_PC_ZERO] = 180;   // clean terminal - must NOT show
	cov.ring_drops = 5; cov.queue_drops = 0;
	cov.managed_naming_off = 1;
	cov.prearm_drops = 4;
	cov.depth_capped = 1;
	emit_json(&cov, j, sizeof(j));
	CHECK(strstr(j, "\"type\":\"coverage\""));
	CHECK(strstr(j, "\"engine\":\"syscalls\""));
	CHECK(strstr(j, "\"truncated\":3"));
	CHECK(strstr(j, "\"no_fde\":12"));
	CHECK(strstr(j, "\"ra_readfault\":2"));
	CHECK(strstr(j, "\"ring\":5"));
	CHECK(strstr(j, "\"managed_naming_off\":true"));
	CHECK(strstr(j, "\"prearm_drops\":4"));
	CHECK(strstr(j, "\"depth_capped\":1"));
	CHECK(!strstr(j, "snap_pc_zero"));      // clean terminal omitted
	CHECK(!strstr(j, "\"clean\""));          // degraded run is not clean

	// 2. Zero fields omitted: a funcs run with only truncation.
	struct ares_coverage f = {0};
	f.engine = "funcs";
	f.snaps_total = 10; f.snaps_truncated = 1;
	emit_json(&f, j, sizeof(j));
	CHECK(strstr(j, "\"engine\":\"funcs\""));
	CHECK(strstr(j, "\"truncated\":1"));
	CHECK(!strstr(j, "prearm_drops"));       // zero -> omitted
	CHECK(!strstr(j, "\"cfi\""));            // no walks -> omitted
	CHECK(!strstr(j, "managed_naming_off")); // false -> omitted

	// 3. Clean run collapses.
	struct ares_coverage clean = {0};
	clean.engine = "syscalls";
	clean.snaps_total = 20;   // captured, none truncated
	clean.cfi_walks = 20;     // all clean terminals
	clean.cfi_stop[CFI_SNAP_PC_ZERO] = 20;
	emit_json(&clean, j, sizeof(j));
	CHECK(strstr(j, "\"clean\":true"));
	CHECK(!strstr(j, "truncated"));

	// 4. decode_partial (correlate).
	struct ares_coverage c = {0};
	c.engine = "correlate"; c.decode_partial = 1;
	emit_json(&c, j, sizeof(j));
	CHECK(strstr(j, "\"decode_partial\":true"));

	// 5. Stop-name mapping.
	CHECK(strcmp(ares_cfi_stop_name(CFI_NO_FDE), "no_fde") == 0);
	CHECK(strcmp(ares_cfi_stop_name(CFI_RUN_FAIL), "run_fail") == 0);
	CHECK(ares_cfi_stop_is_blind(CFI_NO_FDE));
	CHECK(!ares_cfi_stop_is_blind(CFI_SNAP_PC_ZERO));

	printf("test_coverage: %d checks passed\n", checks);
	return 0;
}
