// SPDX-License-Identifier: GPL-2.0
// Firewall-aware capability registry. The detectability firewall's one real
// invariant — "a stealthy run attaches zero uprobes" — is governed solely by
// whether a loaded BPF object writes into the target's userspace memory. This
// table is that fact in one auditable place: only uprobe-bearing objects set
// writes_target_memory. Advisory by design: each subcommand loads one object of
// known/documented loudness — the value is the audit point + regression guard.
// Enforcement only makes sense under an implicit composition layer (not built).
#ifndef __ANUBEE_CAPABILITIES_H
#define __ANUBEE_CAPABILITIES_H

#include <stdbool.h>

struct anubee_bpf_object {
    const char *name;             // capability/object name (argv[1])
    bool writes_target_memory;    // true == plants a uprobe BRK/trampoline
};

// The registry and its length.
const struct anubee_bpf_object *anubee_bpf_objects(int *count);

// True if the named object writes target memory; false if unknown.
bool anubee_object_writes_target(const char *name);

// The quiet-mode invariant: false iff any loaded object writes target memory.
bool anubee_quiet_config_ok(const char *const *loaded, int n);

#endif /* __ANUBEE_CAPABILITIES_H */
