// SPDX-License-Identifier: GPL-2.0
#ifndef ARES_DUMP_EMIT_H
#define ARES_DUMP_EMIT_H

struct jbuf;  /* common/emit.h */

// SYM1 Phase 3: dump's machine channel — one manifest record per rebuilt
// module, mirroring the emit contract every other engine already has
// (funcs_emit_call, corr_emit_syscall, mod_emit_*: pure builder, no libbpf
// deps, host-testable). base is the module's live load address.
void dump_emit_module(struct jbuf *j, const char *module, const char *path,
                      unsigned long long base, int pid, int raw);

#endif /* ARES_DUMP_EMIT_H */
