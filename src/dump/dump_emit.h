// SPDX-License-Identifier: GPL-2.0
#ifndef ANUBEE_DUMP_EMIT_H
#define ANUBEE_DUMP_EMIT_H

struct jbuf;  /* common/emit.h */

// SYM1 Phase 3: dump's machine channel — one manifest record per rebuilt
// module, mirroring the emit contract every other engine already has
// (funcs_emit_call, corr_emit_syscall, mod_emit_*: pure builder, no libbpf
// deps, host-testable). base is the module's live load address.
void dump_emit_module(struct jbuf *j, const char *module, const char *path,
                      unsigned long long base, int pid, int raw);

// {"type":"modcmp","module":"..","path":"..","base":"0x..","pid":N,
//  "state":"match"|"differ"|"nofile"|"apk"|"unreadable",
//  "mem_sha256":".."|null,"file_sha256":".."|null}
// dump --check's machine channel: does this module's executable memory still
// match its backing file? Only PT_LOAD segments with PF_X are hashed - .data /
// .got / .data.rel.ro legitimately differ once the linker has run, so hashing
// them would report "differ" for every library on the device.
// state: "match" = exec pages identical to disk. "differ" = they are not (the
// unpacking / self-modification signal). "nofile" = no disk backing (deleted or
// anonymous), nothing to compare. "apk" = the module is backed by an APK member
// (extractNativeLibs=false, the modern AGP default, maps .so files straight out
// of base.apk) but no stored member starts at the observed file offset - a
// compressed (non-stored) member, or an APK whose central directory could not
// be parsed. This means only "the baseline did not resolve", not "this module
// came from an APK" - APK-embedded libraries are otherwise a supported
// baseline: the stored member is resolved via the APK's central directory and
// compared like any other file. "unreadable" = a short or failed
// /proc/<pid>/mem read, a bad ELF header, an unusable phdr table, or a failed
// allocation, so NO verdict is claimed - reporting "differ" here would paint a
// false positive on a clean library.
// mem_sha256/file_sha256: hex digests of the concatenated PF_X segment bytes, or
// NULL -> JSON null when that side has no meaningful digest (every state except
// match/differ). Caller-computed, keeping this builder free of the hashing and
// ELF logic - same pattern as mod_emit's caller-decoded fields.
void dump_emit_modcmp(struct jbuf *j, const char *module, const char *path,
                      unsigned long long base, int pid, const char *state,
                      const char *mem_sha256, const char *file_sha256);

#endif /* ANUBEE_DUMP_EMIT_H */
