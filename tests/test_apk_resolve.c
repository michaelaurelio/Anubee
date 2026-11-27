// SPDX-License-Identifier: GPL-2.0
// Host test: resolve probe specs against stored members of an APK.
#include "common/probe_resolve.h"
#include "common/sym_apk.h"
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                                 \
    checks++;                                                 \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

// ---- minimal ZIP (stored-only) writer, mirroring sym_apk.c's reader --------

#define ZBUF_CAP (1 << 20)
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
// exactly as sym_apk.c's apk_parse() computes them.
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

static void noop_log(const char *fmt, ...) { (void)fmt; }
static const char *fixture = "tests/fixtures/eh_frame_sample.so";

static unsigned char *slurp(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)sz);
    if (!b || fread(b, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(b); return NULL; }
    fclose(f);
    *n = (size_t)sz;
    return b;
}

// True when out[0..n) contains a target at `off` named `name`.
static int has_target(const probe_target_t *out, int n, unsigned long off, const char *name)
{
    for (int i = 0; i < n; i++)
        if (out[i].offset == off && strcmp(out[i].func_name, name) == 0)
            return 1;
    return 0;
}

int main(void)
{
    elf_version(EV_CURRENT);

    size_t fixlen = 0;
    unsigned char *fixb = slurp(fixture, &fixlen);
    CHECK(fixb != NULL, "fixture: readable");
    if (!fixb) return 1;

    // Three stored members: the fixture twice (arm64 and 32-bit dirs) plus a
    // non-ELF blob, so the resolver's ABI filter and ELF-parse guard both run.
    struct zentry e0, e1, e2;
    zpos = 0;
    add_stored_entry(&e0, "lib/arm64-v8a/libfix.so", fixb, (uint32_t)fixlen);
    add_stored_entry(&e1, "lib/armeabi-v7a/libarm32.so", fixb, (uint32_t)fixlen);
    add_stored_entry(&e2, "lib/arm64-v8a/libnotelf.so", "NOTANELF", 8);

    uint32_t cd_off = (uint32_t)zpos;
    add_central_dir(&e0);
    add_central_dir(&e1);
    add_central_dir(&e2);
    uint32_t cd_size = (uint32_t)zpos - cd_off;

    put_le32(0x06054b50);  // EOCD signature
    put_le16(0);             // disk number
    put_le16(0);             // disk with CD
    put_le16(3);             // entries on this disk
    put_le16(3);             // total entries
    put_le32(cd_size);       // CD size
    put_le32(cd_off);        // CD offset
    put_le16(0);              // comment length

    char apk[64];
    snprintf(apk, sizeof(apk), "/tmp/test_apk_resolve_%d.apk", (int)getpid());
    FILE *f = fopen(apk, "wb");
    CHECK(f != NULL, "apk: fopen for write");
    if (!f) { free(fixb); return 1; }
    CHECK(fwrite(zbuf, 1, zpos, f) == zpos, "apk: fwrite full buffer");
    fclose(f);

    uint64_t data_start = 0;
    int cnt = apk_so_count(apk);
    for (int i = 0; i < cnt; i++) {
        struct apk_so_ref r;
        if (apk_so_get(apk, i, &r) && strcmp(r.name, "libfix.so") == 0)
            data_start = r.data_start;
    }
    CHECK(data_start != 0, "apk: libfix.so member located");

    // Plain-file reference offsets: the in-APK offsets must be data_start plus
    // exactly what the on-disk resolver returns for the same symbol.
    custom_probe_spec_t spec;
    probe_target_t plain;
    CHECK(parse_custom_probe_spec("libfix.so!register_tm_clones", &spec, noop_log) == 0,
          "parse: register_tm_clones spec");
    CHECK(resolve_custom_spec_for_path(getpid(), fixture, &spec, &plain) == 0,
          "plain: register_tm_clones resolves");
    unsigned long plain_reg = plain.offset;
    CHECK(plain_reg != 0, "plain: register_tm_clones offset nonzero");

    CHECK(parse_custom_probe_spec("libfix.so!deregister_tm_clones", &spec, noop_log) == 0,
          "parse: deregister_tm_clones spec");
    CHECK(resolve_custom_spec_for_path(getpid(), fixture, &spec, &plain) == 0,
          "plain: deregister_tm_clones resolves");
    unsigned long plain_dereg = plain.offset;
    CHECK(plain_dereg != 0, "plain: deregister_tm_clones offset nonzero");

    // 1. exact symbol in an arm64 member: offset is data_start + plain offset.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libfix.so!register_tm_clones", &spec, noop_log) == 0,
              "exact: parse");
        CHECK(custom_spec_matches_apk(&spec, apk), "exact: spec matches the apk");
        int n = resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8);
        CHECK(n == 1, "exact: one target");
        CHECK(n == 1 && out[0].offset == data_start + plain_reg,
              "exact: offset == data_start + plain offset");
        CHECK(n == 1 && strcmp(out[0].mod_path, apk) == 0, "exact: mod_path is the apk");
        CHECK(n == 1 && strcmp(out[0].func_name, "register_tm_clones") == 0,
              "exact: func_name");
        CHECK(n == 1 && out[0].pid == getpid(), "exact: pid");
    }

    // 2. func regex collects every matching symbol in the member.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libfix.so!/_clones$/", &spec, noop_log) == 0,
              "regex: parse");
        int n = resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8);
        CHECK(n == 2, "regex: two targets");
        CHECK(has_target(out, n, (unsigned long)(data_start + plain_reg), "register_tm_clones"),
              "regex: register offset");
        CHECK(has_target(out, n, (unsigned long)(data_start + plain_dereg), "deregister_tm_clones"),
              "regex: deregister offset");
    }

    // 3. raw @offset is relative to the member's ELF start.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libfix.so@0x10", &spec, noop_log) == 0,
              "raw: parse");
        int n = resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8);
        CHECK(n == 1, "raw: one target");
        CHECK(n == 1 && out[0].offset == data_start + 0x10, "raw: data_start + 0x10");
    }

    // 4. glob and /regex/ module forms.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libf*.so!register_tm_clones", &spec, noop_log) == 0,
              "glob: parse");
        CHECK(custom_spec_matches_apk(&spec, apk), "glob: matches");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 1, "glob: one target");
    }
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("/^libfix\\.so$/!register_tm_clones", &spec, noop_log) == 0,
              "regex mod: parse");
        CHECK(custom_spec_matches_apk(&spec, apk), "regex mod: matches");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 1,
              "regex mod: one target");
    }

    // 5. a member in a non-arm64 ABI directory never participates.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libarm32.so!register_tm_clones", &spec, noop_log) == 0,
              "abi: parse");
        CHECK(!custom_spec_matches_apk(&spec, apk), "abi: 32-bit member does not match");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 0,
              "abi: no target");
    }

    // 6. unknown member, unknown symbol, non-ELF member.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libnone.so!x", &spec, noop_log) == 0, "absent: parse");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 0,
              "absent: unknown member resolves nothing");

        CHECK(parse_custom_probe_spec("libfix.so!no_such_symbol", &spec, noop_log) == 0,
              "absent: symbol parse");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 0,
              "absent: unknown symbol resolves nothing");

        CHECK(parse_custom_probe_spec("libnotelf.so!x", &spec, noop_log) == 0,
              "absent: notelf parse");
        CHECK(custom_spec_matches_apk(&spec, apk), "absent: notelf member name matches");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 0,
              "absent: non-ELF member resolves nothing (no crash)");
    }

    // 7. a non-APK path is never treated as an APK.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("libfix.so!register_tm_clones", &spec, noop_log) == 0,
              "non-apk: parse");
        CHECK(!custom_spec_matches_apk(&spec, fixture), "non-apk: does not match");
        CHECK(resolve_custom_spec_in_apk(getpid(), fixture, &spec, out, 8) == 0,
              "non-apk: resolves nothing");
    }

    // 8. a MODULE containing '/' is a path pattern, never a member name.
    {
        probe_target_t out[8];
        CHECK(parse_custom_probe_spec("/data/x/libfix.so!register_tm_clones", &spec, noop_log) == 0,
              "path mod: parse");
        CHECK(!custom_spec_matches_apk(&spec, apk), "path mod: does not match a member");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 8) == 0,
              "path mod: resolves nothing");
    }

    // 9. max caps the number of targets.
    {
        probe_target_t out[1];
        CHECK(parse_custom_probe_spec("libfix.so!/_clones$/", &spec, noop_log) == 0,
              "cap: parse");
        CHECK(resolve_custom_spec_in_apk(getpid(), apk, &spec, out, 1) == 1,
              "cap: stops at max");
    }

    unlink(apk);
    free(fixb);

    printf("\n%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
