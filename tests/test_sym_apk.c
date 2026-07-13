// SPDX-License-Identifier: GPL-2.0
// Host-compilable unit test for common/sym_apk.c's ZIP central-directory
// reader (apk_list_sos/apk_so_name) — the MT3 fix's packed-native enumerator.
//
// Links only sym_apk.c (no libelf/lzma dependency there — see plan). sym_apk.c
// calls the shared pread_all() normally defined in sym_elf.c; since sym_elf.c
// isn't linked here (it drags in <lzma.h>/<elf.h> for unrelated reasons), this
// file provides its own global-linkage definition, byte-identical to the real
// one, purely to satisfy the link.
#include "common/sym_apk.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int pread_all(int fd, void *buf, size_t n, off_t off)
{
    char *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r; off += r;
    }
    return 0;
}

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                                 \
    checks++;                                                 \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

// ---- minimal ZIP (stored-only) writer, mirroring sym_apk.c's reader --------

#define ZBUF_CAP 4096
static uint8_t zbuf[ZBUF_CAP];
static size_t  zpos;

static void put_bytes(const void *p, size_t n) { memcpy(zbuf + zpos, p, n); zpos += n; }
static void put_le16(uint16_t v) { uint8_t b[2] = { v & 0xff, (v >> 8) & 0xff }; put_bytes(b, 2); }
static void put_le32(uint32_t v) {
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    put_bytes(b, 4);
}

struct zentry { const char *name; uint32_t lhdr_off; uint32_t data_start; uint32_t size; };

// Appends one stored (method=0) local file header + data; records offsets
// exactly as sym_apk.c's apk_parse() computes them (lhdr_off + 30 + fname_len
// + extra_len, extra_len always 0 here).
static void add_stored_entry(struct zentry *e, const char *name, const void *data, uint32_t len)
{
    e->name     = name;
    e->lhdr_off = (uint32_t)zpos;
    uint16_t nlen = (uint16_t)strlen(name);

    put_le32(0x04034b50);  // local file header signature
    put_le16(20);           // version needed
    put_le16(0);            // flags
    put_le16(0);            // method: 0 = stored
    put_le16(0);            // mod time
    put_le16(0);            // mod date
    put_le32(0);            // crc32 (unchecked by the reader)
    put_le32(len);          // compressed size
    put_le32(len);          // uncompressed size
    put_le16(nlen);         // filename length
    put_le16(0);             // extra length
    put_bytes(name, nlen);

    e->data_start = (uint32_t)zpos;
    e->size       = len;
    put_bytes(data, len);
}

static void add_central_dir(const struct zentry *e)
{
    uint16_t nlen = (uint16_t)strlen(e->name);
    put_le32(0x02014b50);  // central directory signature
    put_le16(0);             // version made by
    put_le16(20);            // version needed
    put_le16(0);             // flags
    put_le16(0);             // method: 0 = stored
    put_le16(0);             // mod time
    put_le16(0);             // mod date
    put_le32(0);             // crc32
    put_le32(e->size);       // compressed size
    put_le32(e->size);       // uncompressed size
    put_le16(nlen);          // filename length
    put_le16(0);              // extra length
    put_le16(0);              // comment length
    put_le16(0);              // disk number start
    put_le16(0);              // internal attrs
    put_le32(0);              // external attrs
    put_le32(e->lhdr_off);    // local header offset
    put_bytes(e->name, nlen);
}

int main(void)
{
    struct zentry ea, eb;
    zpos = 0;
    add_stored_entry(&ea, "lib/arm64-v8a/liba.so", "AAAA", 4);
    add_stored_entry(&eb, "lib/arm64-v8a/libb.so", "BBBBBB", 6);

    uint32_t cd_off = (uint32_t)zpos;
    add_central_dir(&ea);
    add_central_dir(&eb);
    uint32_t cd_size = (uint32_t)zpos - cd_off;

    put_le32(0x06054b50);  // EOCD signature
    put_le16(0);             // disk number
    put_le16(0);             // disk with CD
    put_le16(2);             // entries on this disk
    put_le16(2);             // total entries
    put_le32(cd_size);       // CD size
    put_le32(cd_off);        // CD offset
    put_le16(0);              // comment length

    char path[64];
    snprintf(path, sizeof(path), "/tmp/test_sym_apk_%d.apk", (int)getpid());
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "fixture: fopen for write");
    if (!f) return 1;
    CHECK(fwrite(zbuf, 1, zpos, f) == zpos, "fixture: fwrite full buffer");
    fclose(f);

    // --- apk_list_sos: enumerate both stored .so entries ---
    struct apk_so_ref refs[8];
    int n = apk_list_sos(path, refs, 8);
    CHECK(n == 2, "list_sos: returns 2 entries");
    if (n == 2) {
        CHECK(strcmp(refs[0].name, "liba.so") == 0, "list_sos: entry 0 name");
        CHECK(refs[0].data_start == ea.data_start, "list_sos: entry 0 data_start");
        CHECK(refs[0].size == 4, "list_sos: entry 0 size");
        CHECK(strcmp(refs[1].name, "libb.so") == 0, "list_sos: entry 1 name");
        CHECK(refs[1].data_start == eb.data_start, "list_sos: entry 1 data_start");
        CHECK(refs[1].size == 6, "list_sos: entry 1 size");
    }

    // --- apk_so_name: exact-offset reverse lookup (existing API) ---
    const char *hit = apk_so_name(path, ea.data_start);
    CHECK(hit != NULL && strcmp(hit, "liba.so") == 0, "so_name: exact data_start match");

    // A mid-range offset (inside the entry's byte range but not its exact
    // data_start) must NOT match via apk_so_name — it's exact-only. This is
    // exactly why lib.c's MT3 fix uses a [data_start, data_start+size) range
    // test instead of calling apk_so_name for the actually-loaded segment.
    const char *miss = apk_so_name(path, ea.data_start + 1);
    CHECK(miss == NULL, "so_name: mid-range offset does not exact-match");

    // Not an APK path at all.
    CHECK(apk_so_name("/system/lib64/libc.so", 0) == NULL, "so_name: non-.apk path rejected");

    unlink(path);

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
