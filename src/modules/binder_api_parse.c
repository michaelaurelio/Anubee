// SPDX-License-Identifier: GPL-2.0
// Pure helpers for `anubee mod binder-api`: Parcel interface-token decode and
// AIDL method naming from DEX. See binder_api_parse.h.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "modules/binder_api_parse.h"

// ---- Parcel token ------------------------------------------------------------

static int token_len(const unsigned char *raw, size_t n)
{
    if (n < BINDER_TOKEN_OFF + 4)
        return -1;
    int32_t len;
    memcpy(&len, raw + BINDER_TOKEN_OFF, 4);
    if (len <= 0 || len > 1024)
        return -1;
    if ((size_t)BINDER_TOKEN_OFF + 4 + 2 * (size_t)len > n)
        return -1;
    return len;
}

int binder_parcel_token(const unsigned char *raw, size_t n, char *out, size_t outsz)
{
    int len = token_len(raw, n);
    if (len < 0 || (size_t)len + 1 > outsz)
        return -1;
    const unsigned char *p = raw + BINDER_TOKEN_OFF + 4;
    for (int i = 0; i < len; i++) {
        unsigned u = p[2 * i] | (unsigned)p[2 * i + 1] << 8;
        if (u < 0x20 || u == 0x7f)
            return -1;                 // not text: not an interface token
        out[i] = u < 0x80 ? (char)u : '?';
    }
    out[len] = '\0';
    return len;
}

uint64_t binder_token_hash(const unsigned char *raw, size_t n)
{
    int len = token_len(raw, n);
    if (len < 0)
        return 0;
    const unsigned char *p = raw + BINDER_TOKEN_OFF + 4;
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 2 * len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

// String16 at *o: int32 length (-1 = null) + UTF-16 chars + NUL, padded to
// 4. Returns 1 (string, copied to buf as ASCII), 0 (null) or -1 (not a
// plausible string: bad length, truncated, or a char outside 0x20..0x7e;
// spaces rejected unless allow_space). Advances *o on success.
static int rd_str16(const unsigned char *raw, size_t n, size_t *o, char *buf, size_t bufsz,
                    int allow_space)
{
    if (*o + 4 > n) return -1;
    int32_t l;
    memcpy(&l, raw + *o, 4);
    if (l == -1) { buf[0] = '\0'; *o += 4; return 0; }
    if (l <= 0 || (size_t)l >= bufsz || *o + 4 + 2 * ((size_t)l + 1) > n) return -1;
    const unsigned char *p = raw + *o + 4;
    for (int32_t i = 0; i < l; i++) {
        unsigned u = p[2 * i] | (unsigned)p[2 * i + 1] << 8;
        if (u > 0x7e || u < 0x20 || (u == 0x20 && !allow_space)) return -1;
        buf[i] = (char)u;
    }
    buf[l] = '\0';
    *o += (4 + 2 * ((size_t)l + 1) + 3) & ~(size_t)3;
    return 1;
}

static int uri_char(unsigned c)
{
    return c > 0x20 && c < 0x7f;
}

int binder_cp_describe(const unsigned char *raw, size_t n, int is_call,
                       struct binder_cp_detail *out)
{
    memset(out, 0, sizeof *out);
    int tl = token_len(raw, n);
    size_t start = tl > 0 ? ((size_t)BINDER_TOKEN_OFF + 4 + 2 * ((size_t)tl + 1) + 3) & ~(size_t)3
                          : (size_t)BINDER_TOKEN_OFF + 4;
    static const char scheme[] = "content://";
    const size_t sl = sizeof scheme - 1;

    for (size_t o = start; o + 4 <= n; o += 4) {
        if (is_call) {
            // authority, method, arg (nullable), then the extras Bundle:
            // null (-1), empty (0), or int32 length + "BNDL".
            size_t q = o;
            char a[128], m[128], g[128];
            if (rd_str16(raw, n, &q, a, sizeof a, 0) != 1) continue;
            if (rd_str16(raw, n, &q, m, sizeof m, 0) != 1) continue;
            if (rd_str16(raw, n, &q, g, sizeof g, 1) < 0) continue;
            if (q + 4 > n) continue;
            int32_t x;
            memcpy(&x, raw + q, 4);
            if (!(x == -1 || x == 0 || (q + 8 <= n && !memcmp(raw + q + 4, "BNDL", 4))))
                continue;
            snprintf(out->authority, sizeof out->authority, "%s", a);
            snprintf(out->method, sizeof out->method, "%s", m);
            snprintf(out->arg, sizeof out->arg, "%s", g);
            return 1;
        }
        int32_t l;
        memcpy(&l, raw + o, 4);
        if (l < (int32_t)sl || (size_t)l >= sizeof out->uri) continue;
        // UTF-8 String8 (Android 16's Uri marshalling)
        if (o + 4 + (size_t)l <= n && !memcmp(raw + o + 4, scheme, sl)) {
            int ok = 1;
            for (int32_t i = 0; i < l && ok; i++) ok = uri_char(raw[o + 4 + i]);
            if (ok) {
                memcpy(out->uri, raw + o + 4, (size_t)l);
                out->uri[l] = '\0';
                return 1;
            }
        }
        // UTF-16 String16
        if (o + 4 + 2 * (size_t)l <= n) {
            int ok = 1;
            for (int32_t i = 0; i < l && ok; i++) {
                unsigned u = raw[o + 4 + 2 * i] | (unsigned)raw[o + 5 + 2 * i] << 8;
                ok = (size_t)i < sl ? u == (unsigned char)scheme[i] : uri_char(u);
                if (ok) out->uri[i] = (char)u;
            }
            if (ok) {
                out->uri[l] = '\0';
                return 1;
            }
            out->uri[0] = '\0';
        }
    }
    return 0;
}

// ---- DEX: AIDL Stub TRANSACTION_ constants -------------------------------------

struct bn_entry {
    char *iface;          // owned: "com.example.IFoo"
    const char *method;   // into the DEX string data, or owned_method
    char *owned_method;   // set when the name had to be cut (hand-written _TRANSACTION)
    uint32_t code;
};

struct binder_names {
    struct bn_entry *e;
    int n, cap;
};

struct binder_names *binder_names_new(void)
{
    return calloc(1, sizeof(struct binder_names));
}

void binder_names_free(struct binder_names *bn)
{
    if (!bn) return;
    for (int i = 0; i < bn->n; i++) {
        free(bn->e[i].iface);
        free(bn->e[i].owned_method);
    }
    free(bn->e);
    free(bn);
}

int binder_names_count(const struct binder_names *bn)
{
    return bn ? bn->n : 0;
}

const char *binder_names_lookup(const struct binder_names *bn, const char *iface, uint32_t code)
{
    if (!bn || !iface) return NULL;
    for (int i = 0; i < bn->n; i++)
        if (bn->e[i].code == code && !strcmp(bn->e[i].iface, iface))
            return bn->e[i].method;
    return NULL;
}

static int bn_add(struct binder_names *bn, const char *iface, size_t iface_len,
                  const char *method, uint32_t code)
{
    if (bn->n == bn->cap) {
        int nc = bn->cap ? bn->cap * 2 : 256;
        struct bn_entry *ne = realloc(bn->e, (size_t)nc * sizeof *ne);
        if (!ne) return -1;
        bn->e = ne;
        bn->cap = nc;
    }
    char *s = malloc(iface_len + 1);
    if (!s) return -1;
    memcpy(s, iface, iface_len);
    s[iface_len] = '\0';
    bn->e[bn->n++] = (struct bn_entry){ s, method, NULL, code };
    return 0;
}

static int bn_add_owned(struct binder_names *bn, const char *iface, size_t iface_len,
                        char *method, uint32_t code)
{
    if (bn_add(bn, iface, iface_len, method, code) != 0) return -1;
    bn->e[bn->n - 1].owned_method = method;
    return 0;
}

// Bounds-checked cursor over the DEX image.
struct cur { const uint8_t *b; size_t len, pos; int bad; };

static uint32_t rd_u32(const uint8_t *b, size_t len, size_t off, int *bad)
{
    if (off + 4 > len || off + 4 < off) { *bad = 1; return 0; }
    return (uint32_t)b[off] | (uint32_t)b[off + 1] << 8 |
           (uint32_t)b[off + 2] << 16 | (uint32_t)b[off + 3] << 24;
}

static uint16_t rd_u16(const uint8_t *b, size_t len, size_t off, int *bad)
{
    if (off + 2 > len || off + 2 < off) { *bad = 1; return 0; }
    return (uint16_t)(b[off] | b[off + 1] << 8);
}

static uint32_t uleb(struct cur *c)
{
    uint32_t v = 0;
    for (int shift = 0; shift < 35; shift += 7) {
        if (c->pos >= c->len) { c->bad = 1; return 0; }
        uint8_t x = c->b[c->pos++];
        v |= (uint32_t)(x & 0x7f) << shift;
        if (!(x & 0x80)) return v;
    }
    c->bad = 1;
    return 0;
}

// MUTF-8 string data for string_ids[idx] (NUL-terminated in the DEX), or NULL.
static const char *dex_string(const uint8_t *b, size_t len, uint32_t idx)
{
    int bad = 0;
    uint32_t n = rd_u32(b, len, 0x38, &bad), off = rd_u32(b, len, 0x3c, &bad);
    if (bad || idx >= n) return NULL;
    uint32_t data = rd_u32(b, len, (size_t)off + 4 * (size_t)idx, &bad);
    if (bad || data >= len) return NULL;
    struct cur c = { b, len, data, 0 };
    (void)uleb(&c);                              // utf16 length
    if (c.bad) return NULL;
    const char *s = (const char *)b + c.pos;
    if (!memchr(s, '\0', len - c.pos)) return NULL;
    return s;
}

static const char *dex_type(const uint8_t *b, size_t len, uint32_t idx)
{
    int bad = 0;
    uint32_t n = rd_u32(b, len, 0x40, &bad), off = rd_u32(b, len, 0x44, &bad);
    if (bad || idx >= n) return NULL;
    uint32_t sidx = rd_u32(b, len, (size_t)off + 4 * (size_t)idx, &bad);
    return bad ? NULL : dex_string(b, len, sidx);
}

// Skip one encoded_value; if it is a VALUE_INT/SHORT/CHAR/BYTE, store it in *iv
// and set *is_int. Returns 0, or -1 on malformed data.
static int skip_value(struct cur *c, int32_t *iv, int *is_int, int depth);

static int skip_array(struct cur *c, int depth)
{
    uint32_t n = uleb(c);
    for (uint32_t i = 0; i < n && !c->bad; i++) {
        int32_t v; int ii;
        if (skip_value(c, &v, &ii, depth + 1)) return -1;
    }
    return c->bad ? -1 : 0;
}

static int skip_value(struct cur *c, int32_t *iv, int *is_int, int depth)
{
    *is_int = 0;
    if (depth > 8 || c->pos >= c->len) return -1;
    uint8_t hdr = c->b[c->pos++];
    unsigned type = hdr & 0x1f, arg = hdr >> 5;
    switch (type) {
    case 0x00: case 0x02: case 0x03: case 0x04: {     // BYTE SHORT CHAR INT
        unsigned sz = arg + 1;
        if (sz > 4 || c->pos + sz > c->len) return -1;
        uint32_t v = 0;
        for (unsigned i = 0; i < sz; i++) v |= (uint32_t)c->b[c->pos + i] << (8 * i);
        if (type != 0x03 && sz < 4 && (v >> (8 * sz - 1)) & 1)   // sign-extend (CHAR is unsigned)
            v |= ~0u << (8 * sz);
        c->pos += sz;
        *iv = (int32_t)v;
        *is_int = (type == 0x04);
        return 0;
    }
    case 0x06: case 0x10: case 0x11: case 0x15: case 0x16: case 0x17:
    case 0x18: case 0x19: case 0x1a: case 0x1b:
        if (c->pos + arg + 1 > c->len) return -1;
        c->pos += arg + 1;
        return 0;
    case 0x1c:
        return skip_array(c, depth);
    case 0x1d: {                                      // encoded_annotation
        (void)uleb(c);
        uint32_t n = uleb(c);
        for (uint32_t i = 0; i < n && !c->bad; i++) {
            int32_t v; int ii;
            (void)uleb(c);
            if (skip_value(c, &v, &ii, depth + 1)) return -1;
        }
        return c->bad ? -1 : 0;
    }
    case 0x1e: case 0x1f:                             // NULL, BOOLEAN
        return 0;
    default:
        return -1;
    }
}

#define TX_PREFIX "TRANSACTION_"
#define TX_SUFFIX "_TRANSACTION"
#define STUB_SUFFIX "$Stub;"
#define ACC_INTERFACE 0x0200

// Two shapes name a Binder method:
//  - AIDL: class `<Iface>$Stub` with `TRANSACTION_<method> = code`;
//  - hand-written (e.g. android.content.IContentProvider): the interface
//    itself with `<NAME>_TRANSACTION = code`.

static int index_class(struct binder_names *bn, const uint8_t *b, size_t len, size_t cdef)
{
    int bad = 0;
    uint32_t class_idx = rd_u32(b, len, cdef, &bad);
    uint32_t acc       = rd_u32(b, len, cdef + 4, &bad);
    uint32_t data_off  = rd_u32(b, len, cdef + 24, &bad);
    uint32_t sv_off    = rd_u32(b, len, cdef + 28, &bad);
    if (bad || !data_off || !sv_off) return 0;
    const char *desc = dex_type(b, len, class_idx);
    if (!desc || desc[0] != 'L') return 0;
    size_t dl = strlen(desc), sl = strlen(STUB_SUFFIX);
    int aidl = dl > sl + 1 && !strcmp(desc + dl - sl, STUB_SUFFIX);
    if (!aidl && !(acc & ACC_INTERFACE)) return 0;
    if (!aidl) sl = 1;                       // just the trailing ';'

    // "Lcom/x/IFoo$Stub;" (or "Lcom/x/IFoo;") -> "com.x.IFoo"
    char iface[256];
    size_t il = dl - sl - 1;
    if (il >= sizeof iface) return 0;
    for (size_t i = 0; i < il; i++) iface[i] = desc[1 + i] == '/' ? '.' : desc[1 + i];

    uint32_t fid_n = rd_u32(b, len, 0x50, &bad), fid_off = rd_u32(b, len, 0x54, &bad);
    if (bad) return 0;

    struct cur cd = { b, len, data_off, 0 };
    uint32_t nstatic = uleb(&cd);
    (void)uleb(&cd); (void)uleb(&cd); (void)uleb(&cd);
    struct cur sv = { b, len, sv_off, 0 };
    uint32_t nvals = uleb(&sv);
    if (cd.bad || sv.bad) return 0;

    int added = 0, first = bn->n;
    const char *wire = NULL;                      // DESCRIPTOR/descriptor constant
    uint32_t fidx = 0;
    for (uint32_t i = 0; i < nstatic && i < nvals; i++) {
        fidx += uleb(&cd);
        (void)uleb(&cd);                          // access flags
        // Peek: a VALUE_STRING (0x17) may be the interface's wire descriptor.
        int is_str = 0;
        uint32_t str_idx = 0;
        if (sv.pos < sv.len && (sv.b[sv.pos] & 0x1f) == 0x17) {
            unsigned sz = (sv.b[sv.pos] >> 5) + 1;
            if (sz <= 4 && sv.pos + 1 + sz <= sv.len) {
                for (unsigned k = 0; k < sz; k++) str_idx |= (uint32_t)sv.b[sv.pos + 1 + k] << (8 * k);
                is_str = 1;
            }
        }
        int32_t v = 0; int is_int = 0;
        if (cd.bad || skip_value(&sv, &v, &is_int, 0)) break;
        if ((!is_int && !is_str) || fidx >= fid_n) continue;
        uint32_t name_idx = rd_u32(b, len, (size_t)fid_off + 8 * (size_t)fidx + 4, &bad);
        uint16_t type_idx = rd_u16(b, len, (size_t)fid_off + 8 * (size_t)fidx + 2, &bad);
        if (bad) break;
        const char *name = dex_string(b, len, name_idx);
        const char *type = dex_type(b, len, type_idx);
        if (!name || !type)
            continue;
        if (is_str) {
            if ((!strcmp(name, "DESCRIPTOR") || !strcmp(name, "descriptor")) &&
                !strcmp(type, "Ljava/lang/String;"))
                wire = dex_string(b, len, str_idx);
            continue;
        }
        if (strcmp(type, "I"))
            continue;
        if (aidl) {
            if (strncmp(name, TX_PREFIX, sizeof TX_PREFIX - 1)) continue;
            if (bn_add(bn, iface, il, name + sizeof TX_PREFIX - 1, (uint32_t)v) == 0)
                added++;
        } else {
            size_t nl = strlen(name), xl = sizeof TX_SUFFIX - 1;
            if (nl <= xl || strcmp(name + nl - xl, TX_SUFFIX)) continue;
            char *m = strndup(name, nl - xl);   // owned; freed with the entry
            if (m && bn_add_owned(bn, iface, il, m, (uint32_t)v) == 0) added++;
            else free(m);
        }
    }
    // The token on the wire is the descriptor constant, which can differ from
    // the class name (android.database.IBulkCursor is "android.content.IBulkCursor").
    if (wire && *wire && strlen(wire) < 256 && strcmp(wire, bn->n > first ? bn->e[first].iface : "")) {
        for (int i = first; i < bn->n; i++) {
            char *w = strdup(wire);
            if (!w) break;
            free(bn->e[i].iface);
            bn->e[i].iface = w;
        }
    }
    return added;
}

int binder_names_add_dex(struct binder_names *bn, const uint8_t *b, size_t len)
{
    if (!bn || !b || len < 0x70 || memcmp(b, "dex\n", 4)) return 0;
    int bad = 0;
    uint32_t n = rd_u32(b, len, 0x60, &bad), off = rd_u32(b, len, 0x64, &bad);
    if (bad || off > len || n > (len - off) / 32) return 0;
    int added = 0;
    for (uint32_t i = 0; i < n; i++)
        added += index_class(bn, b, len, (size_t)off + 32 * (size_t)i);
    return added;
}

// Index every stored classes*.dex entry of a zip via its central directory.
// Local headers alone aren't enough: real jars set the data-descriptor flag
// (sizes written after the data) on some entries, so a local-header walk
// can't step past them. Zip64 archives are not handled (framework jars
// are far below 4 GiB).
int binder_names_add_jar(struct binder_names *bn, const uint8_t *z, size_t len)
{
    if (!z || len < 22) return 0;
    int bad = 0;
    // End-of-central-directory record: last 22 bytes + up to 64 KiB comment.
    size_t eocd = 0;
    int found = 0;
    size_t lo = len > 22 + 65535 ? len - 22 - 65535 : 0;
    for (size_t p = len - 22 + 1; p-- > lo;) {
        if (rd_u32(z, len, p, &bad) == 0x06054b50) { eocd = p; found = 1; break; }
    }
    if (!found) return 0;
    uint16_t nent = rd_u16(z, len, eocd + 10, &bad);
    uint32_t cd   = rd_u32(z, len, eocd + 16, &bad);
    if (bad || cd >= len) return 0;

    int added = 0;
    size_t pos = cd;
    for (uint16_t i = 0; i < nent; i++) {
        if (rd_u32(z, len, pos, &bad) != 0x02014b50 || bad) break;
        uint16_t method = rd_u16(z, len, pos + 10, &bad);
        uint32_t csize  = rd_u32(z, len, pos + 20, &bad);
        uint16_t nlen   = rd_u16(z, len, pos + 28, &bad);
        uint16_t xlen   = rd_u16(z, len, pos + 30, &bad);
        uint16_t clen   = rd_u16(z, len, pos + 32, &bad);
        uint32_t lho    = rd_u32(z, len, pos + 42, &bad);
        if (bad || pos + 46 + (size_t)nlen > len) break;
        const char *name = (const char *)z + pos + 46;
        if (method == 0 && nlen >= 11 && !memcmp(name, "classes", 7) &&
            !memcmp(name + nlen - 4, ".dex", 4) &&
            rd_u32(z, len, lho, &bad) == 0x04034b50 && !bad) {
            uint16_t lnl = rd_u16(z, len, (size_t)lho + 26, &bad);
            uint16_t lxl = rd_u16(z, len, (size_t)lho + 28, &bad);
            size_t data = (size_t)lho + 30 + lnl + lxl;
            if (!bad && data <= len && csize <= len - data)
                added += binder_names_add_dex(bn, z + data, csize);
        }
        pos += 46 + (size_t)nlen + xlen + clen;
    }
    return added;
}

uint64_t binder_descriptor_hash(const char *descriptor)
{
    if (!descriptor || !*descriptor)
        return 0;
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *c = (const unsigned char *)descriptor; *c; c++) {
        h ^= *c;                       // UTF-16LE low byte (ASCII descriptor)
        h *= 1099511628211ULL;
        h ^= 0;                        // high byte
        h *= 1099511628211ULL;
    }
    return h;
}
