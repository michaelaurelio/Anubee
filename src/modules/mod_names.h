// SPDX-License-Identifier: GPL-2.0
// Pure helpers for `anubee mod`'s analyzer-name list (host-testable, no libbpf).
#ifndef __ANUBEE_MOD_NAMES_H
#define __ANUBEE_MOD_NAMES_H

// Drop repeated analyzer names in place, keeping first-occurrence order.
// Each analyzer owns static skeleton state, so running one twice would make
// the second setup() clobber the first and double every event. on_dup (may
// be NULL) is called once per dropped occurrence. Returns the new count.
int mod_dedupe_names(const char *names[], int n, void (*on_dup)(const char *name));

#endif /* __ANUBEE_MOD_NAMES_H */
