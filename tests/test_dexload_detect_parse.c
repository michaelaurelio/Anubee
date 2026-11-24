// SPDX-License-Identifier: GPL-2.0
// Host unit tests for dexload-detect's pure helpers: payload magic
// classification, kernel path-component join, /proc/<pid>/maps inode lookup,
// payload file naming and copy+sha256.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "modules/dexload_detect_parse.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

int main(void)
{
    // ---- magic classification ----------------------------------------------
    const unsigned char dex[]  = { 'd','e','x','\n','0','3','9','\0' };
    const unsigned char cdex[] = { 'c','d','e','x','0','0','1','\0' };
    const unsigned char zip[]  = { 'P','K',3,4,20,0,8,0 };
    const unsigned char elf[]  = { 0x7f,'E','L','F',2,1,1,0 };
    const unsigned char txt[]  = { '<','?','x','m','l',' ','v','e' };
    const unsigned char baddex[] = { 'd','e','x','\n','a','b','c','\0' };
    CHECK(dl_kind_of(dex, 8) == DL_DEX, "dex magic + version");
    CHECK(dl_kind_of(cdex, 8) == DL_CDEX, "compact dex magic");
    CHECK(dl_kind_of(zip, 8) == DL_ZIP, "zip local-file header");
    CHECK(dl_kind_of(elf, 8) == DL_ELF, "elf magic");
    CHECK(dl_kind_of(txt, 8) == DL_NONE, "xml is not a payload");
    CHECK(dl_kind_of(baddex, 8) == DL_NONE, "dex magic with non-digit version rejected");
    CHECK(dl_kind_of(dex, 3) == DL_NONE, "short buffer rejected");
    CHECK(dl_kind_of(NULL, 8) == DL_NONE, "NULL buffer rejected");

    CHECK(strcmp(dl_kind_name(DL_DEX), "dex") == 0, "name dex");
    CHECK(strcmp(dl_kind_name(DL_ZIP), "zip") == 0, "name zip");
    CHECK(strcmp(dl_kind_name(DL_ELF), "elf") == 0, "name elf");
    CHECK(strcmp(dl_kind_name(99), "none") == 0, "name out of range");
    CHECK(strcmp(dl_kind_ext(DL_ELF), "so") == 0, "elf payload saved as .so");

    // A dropped zip alone is too common (downloads, caches) to alert on; it
    // alerts when something maps it. dex/cdex/elf alert on the drop itself.
    CHECK(dl_drop_alerts(DL_DEX) && dl_drop_alerts(DL_CDEX) && dl_drop_alerts(DL_ELF),
          "dex/cdex/elf drops alert");
    CHECK(!dl_drop_alerts(DL_ZIP), "zip drop alone does not alert");
    CHECK(!dl_drop_alerts(DL_NONE), "none never alerts");

    // ---- path join (kernel gives leaf-first components) ---------------------
    char comps[4][DL_COMP_LEN] = { "p.dex", "files", "com.example.app", "data" };
    char path[256];
    dl_path_join(&comps[0][0], 4, DL_COMP_LEN, 0, path, sizeof path);
    CHECK(strcmp(path, "/data/com.example.app/files/p.dex") == 0, "join reverses components");
    dl_path_join(&comps[0][0], 2, DL_COMP_LEN, 1, path, sizeof path);
    CHECK(strcmp(path, ".../files/p.dex") == 0, "truncated walk marked with .../");
    dl_path_join(&comps[0][0], 0, DL_COMP_LEN, 0, path, sizeof path);
    CHECK(strcmp(path, "/") == 0, "zero components is root");
    char tiny[8];
    dl_path_join(&comps[0][0], 4, DL_COMP_LEN, 0, tiny, sizeof tiny);
    CHECK(strlen(tiny) < sizeof tiny, "join never overflows the output");

    // ---- /proc/<pid>/maps inode lookup ---------------------------------------
    const char *maps =
        "70000000-70100000 r--p 00000000 fd:05 1234      /system/framework/boot.art\n"
        "7a1b000000-7a1b020000 r--p 00000000 fd:2e 99887     /data/data/com.example.app/files/p.dex (deleted)\n"
        "7a1b020000-7a1b030000 r--p 00020000 fd:2e 99887     /data/data/com.example.app/files/p.dex (deleted)\n";
    unsigned long s = 0, e = 0;
    CHECK(dl_maps_find_ino(maps, 99887, &s, &e) == 1, "inode found in maps");
    CHECK(s == 0x7a1b000000UL && e == 0x7a1b020000UL, "first offset-0 mapping returned");
    CHECK(dl_maps_find_ino(maps, 4242, &s, &e) == 0, "absent inode not found");
    CHECK(dl_maps_find_ino(maps, 0, &s, &e) == 0, "inode 0 never matches anon maps");

    // ---- payload naming -------------------------------------------------------
    char name[256];
    dl_payload_name(name, sizeof name, "/data/local/tmp/x", 4321, 99887, DL_DEX);
    CHECK(strcmp(name, "/data/local/tmp/x/4321-99887.dex") == 0, "payload name pid-ino.ext");

    // ---- copy + sha256 ---------------------------------------------------------
    char src[] = "/tmp/dl_srcXXXXXX";
    int fd = mkstemp(src);
    CHECK(fd >= 0, "temp source");
    if (fd >= 0) {
        CHECK(write(fd, "abc", 3) == 3, "write source");
        lseek(fd, 0, SEEK_SET);
        char dst[] = "/tmp/dl_dstXXXXXX";
        int dfd = mkstemp(dst);
        close(dfd);
        char hex[65] = "";
        long long n = dl_copy_fd(fd, dst, hex);
        CHECK(n == 3, "copied 3 bytes");
        CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
              "sha256 of copied bytes");
        char back[8] = "";
        int rfd = open(dst, O_RDONLY);
        CHECK(rfd >= 0 && read(rfd, back, sizeof back) == 3 && memcmp(back, "abc", 3) == 0,
              "destination holds the payload");
        if (rfd >= 0) close(rfd);
        CHECK(dl_copy_fd(-1, dst, hex) < 0, "bad source fd fails");
        close(fd);
        unlink(src);
        unlink(dst);
    }

    // ---- in-memory DEX: header check -----------------------------------------
    unsigned char h[0x70] = { 'd','e','x','\n','0','3','9','\0' };
    h[0x20] = 0x00; h[0x21] = 0x10;                 // file_size = 0x1000
    h[0x24] = 0x70;                                 // header_size
    h[0x28] = 0x78; h[0x29] = 0x56; h[0x2a] = 0x34; h[0x2b] = 0x12;  // endian_tag
    unsigned fs = 0;
    CHECK(dl_dex_header_ok(h, sizeof h, 0x2000, &fs) == 1 && fs == 0x1000, "valid in-memory DEX header");
    CHECK(dl_dex_header_ok(h, sizeof h, 0x800, &fs) == 0, "file_size larger than the region rejected");
    CHECK(dl_dex_header_ok(h, 0x40, 0x2000, &fs) == 0, "short header rejected");
    unsigned char z[0x70] = { 0 };
    CHECK(dl_dex_header_ok(z, sizeof z, 0x2000, &fs) == 0, "not yet copied (zeros) rejected");
    h[0x28] = 0;
    CHECK(dl_dex_header_ok(h, sizeof h, 0x2000, &fs) == 0, "bad endian tag rejected");

    // ---- in-memory DEX: which regions matter ----------------------------------
    const char *msrc = NULL;
    CHECK(dl_memload_wanted("dalvik-DEX data", &msrc) == 1 && msrc == NULL,
          "InMemoryDexClassLoader region wanted, no source file");
    CHECK(dl_memload_wanted("dalvik-classes.dex extracted in memory from /data/user/0/com.example.app/files/p.jar", &msrc) == 1
          && strcmp(msrc, "/data/user/0/com.example.app/files/p.jar") == 0,
          "dex extracted from an app-writable file wanted, source returned");
    CHECK(dl_memload_wanted("dalvik-classes2.dex extracted in memory from /data/local/tmp/x.jar", &msrc) == 1,
          "multidex extraction wanted");
    CHECK(dl_memload_wanted("dalvik-classes.dex extracted in memory from /system_ext/framework/x.jar", &msrc) == 0,
          "extraction from a system partition ignored");
    CHECK(dl_memload_wanted("dalvik-classes.dex extracted in memory from /apex/com.android.art/javalib/y.jar", &msrc) == 0,
          "extraction from an apex ignored");
    CHECK(dl_memload_wanted("dalvik-jit-code-cache", &msrc) == 0, "other dalvik region ignored");
    CHECK(dl_memload_wanted(NULL, &msrc) == 0, "NULL ignored");

    printf("test_dexload_detect_parse: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
