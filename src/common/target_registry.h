// SPDX-License-Identifier: GPL-2.0
// Shared attach-time probe-target registry. Every engine that attaches
// uprobes at a resolved (module, offset) target registers it here, so any
// engine can later map a *runtime* entry_addr back to the symbol that owns
// it via find_target_by_entry_addr() — not just the engine that did the
// attaching. Originally funcs-local (AA4's addr->target hash cache);
// lifted to common so correlate's span-opening [func] lines can show the
// same "mod!func @ 0xoffset" a human already sees on funcs' [event] lines,
// instead of a bare address (ares correlate output-clarity rework).
//
// funcs still owns bulk population through its existing probe_resolve_ctx
// (its .targets/.target_count point straight at target_registry/
// target_registry_count below — same arrays, same direct-write behavior as
// before this file existed). correlate registers one target at a time via
// target_registry_add() right after each successful uprobe attach.
#ifndef __ARES_COMMON_TARGET_REGISTRY_H
#define __ARES_COMMON_TARGET_REGISTRY_H

#include <stdbool.h>
#include <linux/types.h>
#include "common/probe_resolve.h"   // probe_target_t

#define TARGET_REGISTRY_CAP 4096

extern probe_target_t target_registry[TARGET_REGISTRY_CAP];
extern int target_registry_count;

// Append one resolved target (bounds-checked). No dedup — callers that need
// it (funcs' is_duplicate() path) check before calling. Returns false if the
// registry is full; the target is silently not registered and later lookups
// for it just miss (caller falls back to an unresolved/anonymous display).
bool target_registry_add(probe_target_t tgt);

// Resolve a probed function's runtime entry address back to its target
// (module path + symbol + offset) for a given pid. Caches hits in an
// addr->target hash; on a miss, walks /proc/<pid>/maps to compute the static
// file offset, then falls back to a lower-12-bit ASLR-invariant match if the
// direct (offset, mod_path) lookup fails. Thread-safe (own internal lock).
probe_target_t *find_target_by_entry_addr(__u64 entry_addr, pid_t pid, bool *used_fallback);

#endif /* __ARES_COMMON_TARGET_REGISTRY_H */
