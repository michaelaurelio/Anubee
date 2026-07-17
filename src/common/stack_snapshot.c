// SPDX-License-Identifier: GPL-2.0
// Userspace JSON emitter for the shared anubee_stack_snapshot. Pure (no libbpf /
// /proc / ELF deps), so the host test can link it without a cross-toolchain.
#include <linux/types.h>
#include "common/stack_snapshot.h"
#include "common/emit.h"
#include "common/trace_schema.h"

// Build a {"type":"stack",...} JSON object into j. The caller owns the jbuf
// and any I/O (fwrite to a sidecar file); this function only serialises.
void anubee_stack_snapshot_emit_json(struct jbuf *j, const struct anubee_stack_snapshot *s)
{
	jb_s(j, "{\"type\":\"stack\",\"pid\":"); jb_u64(j, s->h.pid);
	jb_s(j, ",\"tid\":");      jb_u64(j, s->h.tid);
	jb_s(j, ",\"stack_id\":"); jb_u64(j, s->stack_id);
	jb_s(j, ",\"pc\":\"");     jb_hex(j, s->pc); jb_c(j, '"');
	jb_s(j, ",\"sp\":\"");     jb_hex(j, s->sp); jb_c(j, '"');
	jb_s(j, ",\"fp\":\"");     jb_hex(j, s->fp); jb_c(j, '"');
	jb_s(j, ",\"lr\":\"");     jb_hex(j, s->lr); jb_c(j, '"');
	jb_s(j, ",\"regs\":[");
	for (int i = 0; i < ANUBEE_SNAP_NREG; i++) {
		if (i) jb_c(j, ',');
		jb_c(j, '"'); jb_hex(j, s->regs[i]); jb_c(j, '"');
	}
	jb_c(j, ']');
	jb_s(j, ",\"tls_base\":\""); jb_hex(j, s->tls_base); jb_c(j, '"');
	jb_s(j, ",\"snap_len\":"); jb_u64(j, s->snap_len);
	jb_s(j, ",\"truncated\":"); jb_u64(j, s->truncated);
	jb_s(j, ",\"snapshot\":\"");
	if (s->snap_len <= sizeof(s->snap))
		jb_b64(j, s->snap, s->snap_len);
	jb_s(j, "\"}\n");
}
