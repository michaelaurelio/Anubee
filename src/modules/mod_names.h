// SPDX-License-Identifier: GPL-2.0
// Pure helpers for `anubee mod`'s analyzer-name list (host-testable, no libbpf).
#ifndef __ANUBEE_MOD_NAMES_H
#define __ANUBEE_MOD_NAMES_H

// Drop repeated analyzer names in place, keeping first-occurrence order.
// Each analyzer owns static skeleton state, so running one twice would make
// the second setup() clobber the first and double every event. on_dup (may
// be NULL) is called once per dropped occurrence. Returns the new count.
int mod_dedupe_names(const char *names[], int n, void (*on_dup)(const char *name));

// Preset name that expands to every stealthy (non-uprobe) analyzer.
#define MOD_PRESET_TRIAGE "triage"

// Replace each MOD_PRESET_TRIAGE entry in names[] (in place, at its position)
// with every analyzer in all[0..nall) for which is_loud() is false, in
// registry order. Run mod_dedupe_names afterwards: an analyzer named both
// explicitly and via the preset appears twice. Expansion stops at cap.
// Returns the new count, or -1 if cap was too small.
int mod_expand_presets(const char *names[], int n, int cap,
                       const char *const *all, int nall,
                       int (*is_loud)(const char *name));

#endif /* __ANUBEE_MOD_NAMES_H */
