// SPDX-License-Identifier: GPL-2.0
// Host unit tests for prop-read's property classifier: what an app is
// checking when it reads a system property -- root/tamper state, emulator
// tells, or device fingerprint.
#include <stdio.h>
#include <string.h>
#include "modules/prop_read_classify.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    CHECK(pr_classify("ro.debuggable") == PR_ROOT, "ro.debuggable: root/tamper check");
    CHECK(pr_classify("ro.build.tags") == PR_ROOT, "build tags: test-keys check");
    CHECK(pr_classify("ro.boot.verifiedbootstate") == PR_ROOT, "verified boot state");
    CHECK(pr_classify("ro.boot.flash.locked") == PR_ROOT, "bootloader lock");
    CHECK(pr_classify("ro.boot.vbmeta.device_state") == PR_ROOT, "vbmeta device state");
    CHECK(pr_classify("init.svc.adbd") == PR_ROOT, "adbd running");
    CHECK(pr_classify("persist.magisk.hide") == PR_ROOT, "magisk prop prefix");

    CHECK(pr_classify("ro.kernel.qemu") == PR_EMULATOR, "qemu kernel flag");
    CHECK(pr_classify("ro.kernel.qemu.gles") == PR_EMULATOR, "qemu gles");
    CHECK(pr_classify("ro.boot.qemu") == PR_EMULATOR, "boot qemu");
    CHECK(pr_classify("qemu.hw.mainkeys") == PR_EMULATOR, "qemu.* prefix");
    CHECK(pr_classify("init.svc.qemu-props") == PR_EMULATOR, "qemu-props service");
    CHECK(pr_classify("init.svc.goldfish-logcat") == PR_EMULATOR, "goldfish service");
    CHECK(pr_classify("ro.hardware") == PR_EMULATOR, "hardware name (goldfish/ranchu)");
    CHECK(pr_classify("ro.product.board") == PR_EMULATOR, "board name");
    CHECK(pr_classify("ro.genymotion.version") == PR_EMULATOR, "genymotion");
    CHECK(pr_classify("init.svc.vbox86-setup") == PR_EMULATOR, "virtualbox setup");
    CHECK(pr_classify("gsm.version.baseband") == PR_EMULATOR, "baseband (empty on emulators)");
    CHECK(pr_classify("ro.build.characteristics") == PR_EMULATOR, "build characteristics (emulator)");

    CHECK(pr_classify("ro.build.fingerprint") == PR_DEVICE, "fingerprint is device info");
    CHECK(pr_classify("ro.product.model") == PR_DEVICE, "model is device info");
    CHECK(pr_classify("ro.serialno") == PR_DEVICE, "serial");
    CHECK(pr_classify("gsm.sim.operator.alpha") == PR_DEVICE, "SIM operator");
    CHECK(pr_classify("persist.sys.timezone") == PR_DEVICE, "timezone (geo-targeting)");
    CHECK(pr_classify("ro.build.version.sdk") == PR_DEVICE, "sdk level");

    CHECK(pr_classify("debug.hwui.renderer") == PR_NONE, "rendering prop is nothing");
    CHECK(pr_classify("") == PR_NONE && pr_classify(NULL) == PR_NONE, "empty / NULL");
    CHECK(strcmp(pr_category_name(PR_EMULATOR), "emulator") == 0, "category name");
    CHECK(pr_category_name(PR_NONE) == NULL, "no category -> NULL");

    // libc reads these in every process at startup: not the app's doing
    CHECK(pr_is_libc_noise("libc.debug.gwp_asan.sample_rate.system_default"), "gwp_asan is libc noise");
    CHECK(pr_is_libc_noise("persist.libc.debug.gwp_asan.max_allocs.sleep"), "persist gwp_asan is libc noise");
    CHECK(pr_is_libc_noise("ro.arch") && pr_is_libc_noise("debug.fdsan"), "ro.arch / fdsan are libc noise");
    CHECK(pr_is_libc_noise("arm64.memtag.process.app_process64"), "memtag is libc noise");
    CHECK(pr_is_libc_noise(""), "empty name is noise");
    CHECK(pr_is_libc_noise("ro.vendor.redirect_socket_calls"), "netd client startup read is noise");
    CHECK(!pr_is_libc_noise("ro.kernel.qemu") && !pr_is_libc_noise("debug.hwui.renderer"),
          "real checks / app-level props are not noise");

    printf("test_prop_read_classify: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
