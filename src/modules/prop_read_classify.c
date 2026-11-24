// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "modules/prop_read_classify.h"

// Exact names, then prefixes ("x." matches "x.anything"); first list hit wins
// in the order root, emulator, device.
static const char *const root_exact[] = {
    "ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags", "ro.build.selinux",
    "ro.boot.verifiedbootstate", "ro.boot.veritymode", "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state", "ro.boot.warranty_bit", "ro.warranty_bit",
    "persist.sys.usb.config", "sys.usb.state", "service.adb.root", "init.svc.adbd",
    "ro.adb.secure", "ro.allow.mock.location", "ro.boot.selinux", NULL,
};
static const char *const root_prefix[] = {
    "persist.magisk.", "ro.magisk.", "init.svc.magisk", "init.svc.ksud", "ro.kernelsu.",
    "persist.sys.xposed", NULL,
};
static const char *const emu_exact[] = {
    "ro.kernel.qemu", "ro.boot.qemu", "ro.hardware", "ro.boot.hardware", "ro.product.board",
    "ro.board.platform", "ro.bootloader", "ro.boot.bootloader", "gsm.version.baseband",
    "ro.build.characteristics", "ro.hardware.audio.primary", "ro.radio.use-ppp",
    "init.svc.qemud", "ro.nox", NULL,
};
static const char *const emu_prefix[] = {
    "qemu.", "ro.kernel.qemu.", "ro.boot.qemu.", "init.svc.qemu", "init.svc.goldfish",
    "init.svc.ranchu", "ro.genymotion.", "ro.genyd.", "init.svc.vbox86", "ro.vbox",
    "init.svc.ldinit", "ro.memu.", NULL,
};
static const char *const dev_exact[] = {
    "ro.build.fingerprint", "ro.product.model", "ro.product.brand", "ro.product.device",
    "ro.product.manufacturer", "ro.product.name", "ro.serialno", "ro.boot.serialno",
    "ro.build.version.release", "ro.build.version.sdk", "ro.build.id",
    "ro.build.version.security_patch", "persist.sys.timezone", "persist.sys.locale",
    "ro.product.locale", "persist.sys.country", NULL,
};
static const char *const dev_prefix[] = {
    "gsm.sim.operator.", "gsm.operator.", "ro.product.vendor.", "ro.product.system.", NULL,
};

static int hit(const char *n, const char *const *exact, const char *const *prefix)
{
    for (int i = 0; exact[i]; i++)
        if (!strcmp(n, exact[i])) return 1;
    for (int i = 0; prefix[i]; i++)
        if (!strncmp(n, prefix[i], strlen(prefix[i]))) return 1;
    return 0;
}

enum pr_category pr_classify(const char *name)
{
    if (!name || !name[0]) return PR_NONE;
    if (hit(name, root_exact, root_prefix)) return PR_ROOT;
    if (hit(name, emu_exact, emu_prefix))   return PR_EMULATOR;
    if (hit(name, dev_exact, dev_prefix))   return PR_DEVICE;
    return PR_NONE;
}

const char *pr_category_name(enum pr_category c)
{
    switch (c) {
    case PR_ROOT:     return "root";
    case PR_EMULATOR: return "emulator";
    case PR_DEVICE:   return "device";
    default:          return NULL;
    }
}

int pr_is_libc_noise(const char *name)
{
    static const char *const exact[] = { "ro.arch", "debug.fdsan", "heapprofd.enable",
                                         "ro.vendor.redirect_socket_calls", NULL };   // libnetd_client
    static const char *const prefix[] = {
        "libc.debug.", "persist.libc.debug.", "arm64.memtag.", "persist.arm64.memtag.",
        "persist.device_config.memory_safety_native.", "heapprofd.", "persist.heapprofd.", NULL,
    };
    if (!name || !name[0]) return 1;
    return hit(name, exact, prefix);
}
