// SPDX-License-Identifier: GPL-2.0
// dex.c — DEX offset->method resolver (src/common). Pure: parses a DEX image and
// maps a byte offset into the file to the Java method whose code_item.insns
// covers it. No libbpf, no /proc, no ELF — host-testable like decode.c.
//
// The DEX image is target-controlled: every read is bounds-checked and every
// table index validated. Malformed entries are skipped; a malformed header
// fails the build. No input can cause an OOB read, infinite loop, or crash.
#include "common/dex.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// ---- DEX header field offsets (standard layout, little-endian) -------------
// Header is 112 bytes. We read individual fields by offset rather than overlay
// a struct, so unaligned/foreign-endian images are handled safely.
#define DEX_HEADER_SIZE      112
#define OFF_STRING_IDS_SIZE  56
#define OFF_STRING_IDS_OFF   60
#define OFF_TYPE_IDS_SIZE    64
#define OFF_TYPE_IDS_OFF     68
#define OFF_METHOD_IDS_SIZE  88
#define OFF_METHOD_IDS_OFF   92
#define OFF_CLASS_DEFS_SIZE  96
#define OFF_CLASS_DEFS_OFF   100

// Table element strides.
#define STRING_ID_STRIDE   4
#define TYPE_ID_STRIDE     4
#define METHOD_ID_STRIDE   8
#define CLASS_DEF_STRIDE  32
#define CODE_ITEM_HEADER  16   // code_item header bytes before insns[]

struct method_range {
    uint32_t start;        // insns start = code_off + 16
    uint32_t end;          // insns end (exclusive)
    uint32_t method_idx;
};

struct dex_method_map {
    uint8_t *img;          // retained private copy of the whole image
    size_t   len;
    uint32_t string_ids_off, string_ids_size;
    uint32_t type_ids_off, type_ids_size;
    uint32_t method_ids_off, method_ids_size;
    struct method_range *ranges;
    size_t   nranges;
};

// ---- little-endian readers (caller has already bounds-checked) -------------
static uint16_t rd_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// True if `count` elements of `stride` bytes starting at `off` fit in [0,len).
// Overflow-safe: the multiply is widened to u64 and compared against len-off.
static int region_ok(size_t len, uint32_t off, uint32_t count, uint32_t stride)
{
    if (off > len)
        return 0;
    uint64_t bytes = (uint64_t)count * stride;
    return bytes <= (uint64_t)(len - off);
}

// Read a ULEB128 from buf[*pos .. len). Advances *pos. Returns 1 on success
// (value in *out), 0 if it would read past len or runs longer than 5 bytes.
static int uleb128(const uint8_t *buf, size_t len, size_t *pos, uint32_t *out)
{
    uint32_t result = 0;
    int shift = 0;
    for (int i = 0; i < 5; i++) {
        if (*pos >= len)
            return 0;
        uint8_t b = buf[(*pos)++];
        result |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *out = result;
            return 1;
        }
        shift += 7;
    }
    return 0;   // more than 5 bytes — malformed
}

static int cmp_range(const void *a, const void *b)
{
    const struct method_range *ra = a, *rb = b;
    if (ra->start < rb->start) return -1;
    if (ra->start > rb->start) return 1;
    return 0;
}

static int push_range(struct dex_method_map *m, size_t *cap,
                      uint32_t start, uint32_t end, uint32_t method_idx)
{
    if (m->nranges == *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        struct method_range *nr = realloc(m->ranges, ncap * sizeof(*nr));
        if (!nr)
            return 0;
        m->ranges = nr;
        *cap = ncap;
    }
    m->ranges[m->nranges].start = start;
    m->ranges[m->nranges].end = end;
    m->ranges[m->nranges].method_idx = method_idx;
    m->nranges++;
    return 1;
}

// Parse one encoded_method group of `count` entries starting at *pos. method_idx
// is a running sum, reset to 0 by the caller per group. Returns 1 on a clean
// pass, 0 if a ULEB read ran out (truncated — caller abandons the rest of this
// class but keeps what it has), -1 on allocation failure (caller aborts the
// whole build). The truncated and OOM cases are kept distinct so an OOM never
// masquerades as a successfully-built but silently-incomplete map.
static int parse_method_group(struct dex_method_map *m, size_t *cap,
                              size_t len, size_t *pos, uint32_t count)
{
    uint32_t method_idx = 0;
    for (uint32_t k = 0; k < count; k++) {
        uint32_t idx_diff, access_flags, code_off;
        if (!uleb128(m->img, len, pos, &idx_diff) ||
            !uleb128(m->img, len, pos, &access_flags) ||
            !uleb128(m->img, len, pos, &code_off))
            return 0;                      // truncated — skip rest of class
        method_idx += idx_diff;            // first entry: relative to 0
        if (code_off == 0)
            continue;                      // abstract/native — no bytecode
        // code_item header is 16 bytes; insns_size (u32) at code_off+12.
        if (code_off > len || (size_t)(len - code_off) < CODE_ITEM_HEADER)
            continue;
        uint32_t insns_size = rd_u32(m->img + code_off + 12);
        uint32_t start = code_off + CODE_ITEM_HEADER;
        uint64_t insns_bytes = (uint64_t)insns_size * 2;
        if (insns_bytes > (uint64_t)(len - start))
            continue;                      // insns run past EOF — skip
        if (method_idx >= m->method_ids_size)
            continue;                      // bad index — skip record
        if (!push_range(m, cap, start, start + (uint32_t)insns_bytes, method_idx))
            return -1;                     // OOM — abort the build
    }
    return 1;
}

struct dex_method_map *dex_map_build(const uint8_t *img, size_t len)
{
    if (!img || len < DEX_HEADER_SIZE)
        return NULL;
    // magic: "dex\n" + version "0NN" + NUL, NN in {035..039}.
    if (memcmp(img, "dex\n", 4) != 0 || img[7] != 0)
        return NULL;
    if (img[4] != '0' || img[5] != '3' || img[6] < '5' || img[6] > '9')
        return NULL;

    struct dex_method_map *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;

    m->len = len;
    m->string_ids_size = rd_u32(img + OFF_STRING_IDS_SIZE);
    m->string_ids_off  = rd_u32(img + OFF_STRING_IDS_OFF);
    m->type_ids_size   = rd_u32(img + OFF_TYPE_IDS_SIZE);
    m->type_ids_off    = rd_u32(img + OFF_TYPE_IDS_OFF);
    m->method_ids_size = rd_u32(img + OFF_METHOD_IDS_SIZE);
    m->method_ids_off  = rd_u32(img + OFF_METHOD_IDS_OFF);
    uint32_t class_defs_size = rd_u32(img + OFF_CLASS_DEFS_SIZE);
    uint32_t class_defs_off  = rd_u32(img + OFF_CLASS_DEFS_OFF);

    if (!region_ok(len, m->string_ids_off, m->string_ids_size, STRING_ID_STRIDE) ||
        !region_ok(len, m->type_ids_off,   m->type_ids_size,   TYPE_ID_STRIDE)   ||
        !region_ok(len, m->method_ids_off, m->method_ids_size, METHOD_ID_STRIDE) ||
        !region_ok(len, class_defs_off,    class_defs_size,    CLASS_DEF_STRIDE)) {
        free(m);
        return NULL;
    }

    m->img = malloc(len);
    if (!m->img) {
        free(m);
        return NULL;
    }
    memcpy(m->img, img, len);

    size_t cap = 0;
    for (uint32_t i = 0; i < class_defs_size; i++) {
        const uint8_t *cd = m->img + class_defs_off + (size_t)i * CLASS_DEF_STRIDE;
        uint32_t class_data_off = rd_u32(cd + 24);   // class_data_off @ +24
        if (class_data_off == 0 || class_data_off >= len)
            continue;                                // no methods / OOB — skip

        size_t pos = class_data_off;
        uint32_t static_fields, instance_fields, direct_methods, virtual_methods;
        if (!uleb128(m->img, len, &pos, &static_fields)   ||
            !uleb128(m->img, len, &pos, &instance_fields) ||
            !uleb128(m->img, len, &pos, &direct_methods)  ||
            !uleb128(m->img, len, &pos, &virtual_methods))
            continue;

        // skip encoded_field entries (two ULEB128 each).
        uint64_t fields = (uint64_t)static_fields + instance_fields;
        int trunc = 0;
        for (uint64_t f = 0; f < fields; f++) {
            uint32_t tmp;
            if (!uleb128(m->img, len, &pos, &tmp) ||
                !uleb128(m->img, len, &pos, &tmp)) { trunc = 1; break; }
        }
        if (trunc)
            continue;

        // direct then virtual methods; each group's method_idx restarts at 0.
        // A truncated group (0) skips the rest of this class; an OOM (<0) aborts.
        int dr = parse_method_group(m, &cap, len, &pos, direct_methods);
        if (dr < 0)
            goto oom;
        if (dr == 0)
            continue;   // truncated/short class — keep prior ranges, next class
        if (parse_method_group(m, &cap, len, &pos, virtual_methods) < 0)
            goto oom;
    }

    if (m->nranges > 1) {
        qsort(m->ranges, m->nranges, sizeof(*m->ranges), cmp_range);
        // Enforce the non-overlapping invariant dex_map_lookup's binary search
        // relies on: a malformed DEX can encode methods whose insns ranges
        // overlap. Keep the lowest-start range of any overlapping run and drop
        // the rest, so lookups stay deterministic and bounded on hostile input.
        size_t w = 1;
        for (size_t r = 1; r < m->nranges; r++) {
            if (m->ranges[r].start >= m->ranges[w - 1].end)
                m->ranges[w++] = m->ranges[r];
        }
        m->nranges = w;
    }

    return m;

oom:
    free(m->img);
    free(m->ranges);
    free(m);
    return NULL;
}

void dex_map_free(struct dex_method_map *m)
{
    if (!m)
        return;
    free(m->img);
    free(m->ranges);
    free(m);
}

// Resolve string id `idx` into out as a NUL-terminated C string. DEX strings are
// MUTF-8 with a ULEB128 utf16-length prefix and a trailing NUL; method/class
// names are ASCII, so we copy raw bytes until NUL (bounded by len and outsz).
// Returns 1 on success, 0 on any bounds failure or if the name exceeds outsz.
static int dex_string(const struct dex_method_map *m, uint32_t idx,
                      char *out, size_t outsz)
{
    if (idx >= m->string_ids_size)
        return 0;
    uint32_t data_off = rd_u32(m->img + m->string_ids_off + (size_t)idx * STRING_ID_STRIDE);
    if (data_off >= m->len)
        return 0;
    size_t pos = data_off;
    uint32_t utf16_len;
    if (!uleb128(m->img, m->len, &pos, &utf16_len))
        return 0;
    size_t o = 0;
    while (pos < m->len) {
        uint8_t c = m->img[pos++];
        if (c == 0)
            break;
        if (o + 1 >= outsz)
            return 0;          // too long for buffer — treat as a miss
        out[o++] = (char)c;
    }
    out[o] = 0;
    return 1;
}

int dex_map_lookup(const struct dex_method_map *m, uint32_t off,
                   char *out, size_t outsz)
{
    if (!m || !out || outsz == 0)
        return 0;

    // binary-search the sorted, non-overlapping ranges for the one holding off.
    const struct method_range *hit = NULL;
    size_t lo = 0, hi = m->nranges;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (off < m->ranges[mid].start)
            hi = mid;
        else if (off >= m->ranges[mid].end)
            lo = mid + 1;
        else { hit = &m->ranges[mid]; break; }
    }
    if (!hit)
        return 0;

    // method_ids[idx]: class_idx (u16 @0), name_idx (u32 @4). Index already
    // validated < method_ids_size at build time, but re-check defensively.
    if (hit->method_idx >= m->method_ids_size)
        return 0;
    const uint8_t *mid_ent = m->img + m->method_ids_off +
                             (size_t)hit->method_idx * METHOD_ID_STRIDE;
    uint16_t class_idx = rd_u16(mid_ent + 0);
    uint32_t name_idx  = rd_u32(mid_ent + 4);

    char name[256];
    if (!dex_string(m, name_idx, name, sizeof(name)))
        return 0;

    // class_idx -> type_ids[class_idx] (descriptor_idx) -> string "Lpkg/Class;".
    if (class_idx >= m->type_ids_size)
        return 0;
    uint32_t desc_idx = rd_u32(m->img + m->type_ids_off +
                               (size_t)class_idx * TYPE_ID_STRIDE);
    char desc[256];
    if (!dex_string(m, desc_idx, desc, sizeof(desc)))
        return 0;

    // descriptor must be a class type "L...;" (array/primitive cannot have methods).
    size_t dl = strlen(desc);
    if (dl < 2 || desc[0] != 'L' || desc[dl - 1] != ';')
        return 0;

    // format out = dotted(desc[1..dl-1]) + "." + name, bounded by outsz.
    size_t o = 0;
    for (size_t i = 1; i + 1 < dl; i++) {
        char c = desc[i] == '/' ? '.' : desc[i];
        if (o + 1 >= outsz)
            return 0;
        out[o++] = c;
    }
    if (o + 1 >= outsz)
        return 0;
    out[o++] = '.';
    for (size_t i = 0; name[i]; i++) {
        if (o + 1 >= outsz)
            return 0;
        out[o++] = name[i];
    }
    out[o] = 0;
    return 1;
}
