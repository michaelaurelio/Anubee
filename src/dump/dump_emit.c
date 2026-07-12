// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builder for ares dump (no libbpf deps, so the host
// test can link it). SYM1 Phase 3: dump previously had no machine channel at
// all — see workspace/ares-output-asymmetry.md §3.5.
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "dump/dump_emit.h"

void dump_emit_module(struct jbuf *j, const char *module, const char *path,
                      unsigned long long base, int pid, int raw)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");   jb_s(j, trace_type_name(TRACE_DUMP)); jb_c(j, '"');
    jb_s(j, ",\"module\":\""); jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"path\":\"");   jb_esc(j, path);   jb_c(j, '"');
    jb_s(j, ",\"base\":\"");   jb_hex(j, base);   jb_c(j, '"');
    jb_s(j, ",\"pid\":");      jb_u64(j, (unsigned long long)pid);
    jb_s(j, ",\"raw\":");      jb_s(j, raw ? "true" : "false");
    jb_c(j, '}');
}
