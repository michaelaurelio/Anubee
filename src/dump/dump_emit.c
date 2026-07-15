// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builder for ares dump (no libbpf deps, so the host
// test can link it). SYM1 Phase 3: dump previously had no machine channel at
// all — see docs/sym1-output-asymmetry.md §3.5.
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

// Emit `"key":"value"` when v is non-NULL, else `"key":null`.
static void jb_str_or_null(struct jbuf *j, const char *key, const char *v)
{
    jb_s(j, ",\""); jb_s(j, key); jb_s(j, "\":");
    if (v) { jb_c(j, '"'); jb_esc(j, v); jb_c(j, '"'); }
    else     jb_s(j, "null");
}

void dump_emit_modcmp(struct jbuf *j, const char *module, const char *path,
                      unsigned long long base, int pid, const char *state,
                      const char *mem_sha256, const char *file_sha256)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");   jb_s(j, trace_type_name(TRACE_MODCMP)); jb_c(j, '"');
    jb_s(j, ",\"module\":\""); jb_esc(j, module); jb_c(j, '"');
    jb_s(j, ",\"path\":\"");   jb_esc(j, path);   jb_c(j, '"');
    jb_s(j, ",\"base\":\"");   jb_hex(j, base);   jb_c(j, '"');
    jb_s(j, ",\"pid\":");      jb_u64(j, (unsigned long long)pid);
    jb_s(j, ",\"state\":\"");  jb_esc(j, state);  jb_c(j, '"');
    jb_str_or_null(j, "mem_sha256",  mem_sha256);
    jb_str_or_null(j, "file_sha256", file_sha256);
    jb_c(j, '}');
}
