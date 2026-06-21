// SPDX-License-Identifier: GPL-2.0
// Firewall-aware capability registry. The detectability firewall's one real
// invariant — "a stealthy run attaches zero uprobes" — is governed solely by
// whether a loaded BPF object writes into the target's userspace memory. This
// table is that fact in one auditable place: only uprobe-bearing objects set
// writes_target_memory. Advisory today (no quiet-mode flag consumes it yet);
// it exists as the single audit point + a regression guard, and is the seam the
// future thin-presets work uses to refuse a loud object in a quiet preset.
#ifndef __ARES_CAPABILITIES_H
#define __ARES_CAPABILITIES_H

#include <stdbool.h>

struct ares_bpf_object {
    const char *name;             // capability/object name (argv[1])
    bool writes_target_memory;    // true == plants a uprobe BRK/trampoline
};

// The registry and its length.
const struct ares_bpf_object *ares_bpf_objects(int *count);

// True if the named object writes target memory; false if unknown.
bool ares_object_writes_target(const char *name);

// The quiet-mode invariant: false iff any loaded object writes target memory.
bool ares_quiet_config_ok(const char *const *loaded, int n);

#endif /* __ARES_CAPABILITIES_H */
