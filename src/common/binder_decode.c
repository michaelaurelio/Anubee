// SPDX-License-Identifier: GPL-2.0
// binder_decode.c — see binder_decode.h. Pure Parcel walk + name tables.

#include "common/binder_decode.h"
#include "common/emit.h"

#include <stdio.h>
#include <string.h>

// Longest String16 accepted by the heuristic walk. Real interface tokens and
// argument strings are far shorter; anything above this is a non-string field
// that happened to look plausible.
#define BINDER_PARCEL_STR_MAX 200

// Describe the String16 at data[off] (n bytes captured). Returns its padded
// size in bytes when accepted and copies up to outsz - 1 characters to out, or
// -1 when the bytes there are not a String16. All reads are bounded by n.
static int parcel_string(const unsigned char *data, size_t n, size_t off,
			 char *out, size_t outsz)
{
	if (n - off < 4)
		return -1;
	int len;
	memcpy(&len, data + off, sizeof len);
	if (len < 1 || len > BINDER_PARCEL_STR_MAX)
		return -1;
	size_t need = 4 + (size_t)len * 2 + 2;     // prefix + chars + NUL
	if (need > n - off)
		return -1;

	const unsigned char *chars = data + off + 4;
	for (int i = 0; i < len; i++) {
		unsigned char lo = chars[(size_t)i * 2];
		unsigned char hi = chars[(size_t)i * 2 + 1];
		if (lo < 0x20 || lo > 0x7e || hi != 0)
			return -1;
	}
	if (chars[(size_t)len * 2] != 0 || chars[(size_t)len * 2 + 1] != 0)
		return -1;

	size_t copy = (size_t)len < outsz - 1 ? (size_t)len : outsz - 1;
	for (size_t i = 0; i < copy; i++)
		out[i] = (char)chars[i * 2];       // UTF-16LE code units -> ASCII
	out[copy] = '\0';
	return (int)((need + 3) & ~(size_t)3);
}

void binder_parse_parcel(const unsigned char *data, size_t n,
			 struct binder_txn_text *out)
{
	memset(out, 0, sizeof *out);
	if (!data)
		return;

	size_t off = 0;
	while (off + 4 <= n) {
		char s[BINDER_STR_MAX];
		int adv = parcel_string(data, n, off, s, sizeof s);
		if (adv < 0) {
			off += 4;                  // not a string: try the next field
			continue;
		}
		if (out->iface[0] == '\0')
			memcpy(out->iface, s, strlen(s) + 1);
		else if (out->nstrs < BINDER_MAX_STRINGS)
			memcpy(out->strs[out->nstrs++], s, strlen(s) + 1);
		off += (size_t)adv;
	}
}

const char *binder_cmd_name(unsigned cmd)
{
	switch (cmd) {
	case 0x40406300u:
		return "BC_TRANSACTION";
	case 0x40486311u:
		return "BC_TRANSACTION_SG";
	default:
		return NULL;
	}
}

void binder_flags_str(unsigned flags, char *out, size_t outsz)
{
	static const struct { unsigned bit; const char *name; } t[] = {
		{ 0x01, "TF_ONE_WAY" },
		{ 0x04, "TF_ROOT_OBJECT" },
		{ 0x08, "TF_STATUS_CODE" },
		{ 0x10, "TF_ACCEPT_FDS" },
		{ 0x20, "TF_CLEAR_BUF" },
		{ 0x40, "TF_UPDATE_TXN" },
	};
	if (outsz == 0)
		return;
	out[0] = '\0';
	size_t pos = 0;
	unsigned rem = flags;
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		if ((rem & t[i].bit) != t[i].bit)
			continue;
		int w = snprintf(out + pos, outsz - pos, "%s%s",
				 pos ? "|" : "", t[i].name);
		if (w > 0 && (size_t)w < outsz - pos)
			pos += (size_t)w;
		rem &= ~t[i].bit;
	}
	if (rem) {
		int w = snprintf(out + pos, outsz - pos, "%s0x%x",
				 pos ? "|" : "", rem);
		if (w > 0 && (size_t)w < outsz - pos)
			pos += (size_t)w;
	}
	if (!out[0])
		snprintf(out, outsz, "0");
}

const char *binder_method_name(const char *iface, unsigned code)
{
	if (!iface)
		return NULL;
	if (strcmp(iface, "android.os.IServiceManager") == 0) {
		switch (code) {
		case 1: return "getService";
		case 2: return "checkService";
		case 3: return "addService";
		case 4: return "listServices";
		}
	} else if (strcmp(iface, "android.content.IContentProvider") == 0) {
		switch (code) {
		case 1:  return "query";
		case 2:  return "getType";
		case 3:  return "insert";
		case 4:  return "delete";
		case 10: return "update";
		case 21: return "call";
		}
	}
	return NULL;
}

void binder_emit_json(struct jbuf *j, const struct binder_txn_view *t)
{
	struct binder_txn_text txt;
	char flags[96];

	binder_parse_parcel(t->data, t->copied, &txt);
	binder_flags_str(t->flags, flags, sizeof flags);

	jb_s(j, "\"binder\":{\"cmd\":\"");
	const char *cn = binder_cmd_name(t->cmd);
	if (cn)
		jb_esc(j, cn);
	else
		jb_hex(j, t->cmd);
	jb_s(j, "\",\"handle\":");      jb_u64(j, t->handle);
	jb_s(j, ",\"code\":");          jb_u64(j, t->code);
	jb_s(j, ",\"flags\":\"");       jb_esc(j, flags); jb_c(j, '"');
	jb_s(j, ",\"data_size\":");     jb_u64(j, t->data_size);

	if (txt.iface[0]) {
		jb_s(j, ",\"interface\":\"");
		jb_esc(j, txt.iface);
		jb_c(j, '"');
	}
	const char *m = binder_method_name(txt.iface, t->code);
	if (m) {
		jb_s(j, ",\"method\":\"");
		jb_esc(j, m);
		jb_c(j, '"');
	}
	if (txt.nstrs > 0) {
		jb_s(j, ",\"strings\":[");
		for (int i = 0; i < txt.nstrs; i++) {
			if (i)
				jb_c(j, ',');
			jb_c(j, '"');
			jb_esc(j, txt.strs[i]);
			jb_c(j, '"');
		}
		jb_c(j, ']');
	}
	jb_s(j, "}");
}
