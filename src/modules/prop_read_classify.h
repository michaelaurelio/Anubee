// SPDX-License-Identifier: GPL-2.0
// prop-read's property classifier (src/modules/prop_read.c): what an app is
// checking when it reads a system property. libc only -- host-testable.
#ifndef __ANUBEE_PROP_READ_CLASSIFY_H
#define __ANUBEE_PROP_READ_CLASSIFY_H

enum pr_category {
    PR_NONE = 0,
    PR_ROOT,       // root / tamper / debug state: ro.debuggable, test-keys, verified boot, adbd, magisk
    PR_EMULATOR,   // emulator tells: qemu, goldfish/ranchu, genymotion, vbox, empty baseband
    PR_DEVICE,     // device fingerprint / targeting: model, serial, SIM operator, timezone, SDK
};

enum pr_category pr_classify(const char *name);
const char *pr_category_name(enum pr_category c);   // "root" "emulator" "device", NULL for PR_NONE

// Properties bionic itself reads in every process at startup (GWP-ASan,
// fdsan, MTE, ro.arch, libnetd_client) -- not the app's doing. 1 = hide from the summary
// table (the JSON summary keeps them).
int pr_is_libc_noise(const char *name);

#endif /* __ANUBEE_PROP_READ_CLASSIFY_H */
