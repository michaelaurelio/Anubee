// Host unit tests for the pure binder transaction parser (common/binder_decode).
//
// Parcels are built byte-for-byte here: int32 fields (the transport header) then
// String16 values (int32 char count, UTF-16LE chars, a 2-byte NUL, padded to 4).
// The parser is a heuristic walk over 4-byte aligned offsets, so these tests pin
// both the accepted shapes and the rejected ones.
#include "common/binder_decode.h"
#include "common/emit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg) do {                                      \
	checks++;                                                  \
	if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }   \
} while (0)

struct parcel {
	unsigned char b[1024];
	size_t n;
};

static void p_i32(struct parcel *p, int v)
{
	memcpy(p->b + p->n, &v, sizeof v);
	p->n += sizeof v;
}

static void p_raw(struct parcel *p, const char *s)
{
	size_t l = strlen(s);
	memcpy(p->b + p->n, s, l);
	p->n += l;
}

// String16: length prefix, UTF-16LE code units, NUL terminator, 4-byte padding.
static void p_str16(struct parcel *p, const char *s)
{
	size_t l = strlen(s);
	p_i32(p, (int)l);
	for (size_t i = 0; i < l; i++) {
		p->b[p->n++] = (unsigned char)s[i];
		p->b[p->n++] = 0;
	}
	p->b[p->n++] = 0;
	p->b[p->n++] = 0;
	while (p->n % 4)
		p->b[p->n++] = 0;
}

// Transport header: strict-mode policy + work-source uid, optionally followed by
// the "SYST" magic and two zero fields (Android 10+).
static void p_header(struct parcel *p, int with_syst)
{
	p_i32(p, 0);
	p_i32(p, 0);
	if (with_syst) {
		p_raw(p, "SYST");
		p_i32(p, 0);
		p_i32(p, 0);
	}
}

static void test_parcel_shapes(void)
{
	struct binder_txn_text t;
	struct parcel p;

	// With the SYST header: the interface is found past the extra fields.
	memset(&p, 0, sizeof p);
	p_header(&p, 1);
	p_str16(&p, "android.content.pm.IPackageManager");
	p_str16(&p, "argument-value");
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(strcmp(t.iface, "android.content.pm.IPackageManager") == 0,
	      "interface found after SYST header");
	CHECK(t.nstrs == 1, "one argument string after SYST header");
	CHECK(strcmp(t.strs[0], "argument-value") == 0, "argument string value");

	// Without the SYST header: the same interface is found.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.os.IServiceManager");
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(strcmp(t.iface, "android.os.IServiceManager") == 0,
	      "interface found without SYST header");
	CHECK(t.nstrs == 0, "no argument strings");

	// Interface plus two argument strings.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.content.IContentProvider");
	p_str16(&p, "settings");
	p_str16(&p, "GET_secure");
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(strcmp(t.iface, "android.content.IContentProvider") == 0,
	      "content provider interface found");
	CHECK(t.nstrs == 2, "two argument strings");
	CHECK(strcmp(t.strs[0], "settings") == 0, "first argument string");
	CHECK(strcmp(t.strs[1], "GET_secure") == 0, "second argument string");

	// Non-string int32 fields between the strings are skipped 4 bytes at a time.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.os.IServiceManager");
	p_i32(&p, 42);
	p_str16(&p, "media.camera");
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(strcmp(t.iface, "android.os.IServiceManager") == 0, "iface before an int field");
	CHECK(t.nstrs == 1 && strcmp(t.strs[0], "media.camera") == 0,
	      "string after an int field");
}

static void test_rejected_shapes(void)
{
	struct binder_txn_text t;
	struct parcel p;

	// n == 0 and a NULL buffer: nothing parsed, output zeroed.
	memset(&t, 0x5a, sizeof t);
	binder_parse_parcel(NULL, 0, &t);
	CHECK(t.iface[0] == 0 && t.nstrs == 0, "empty buffer yields no interface");

	// Length 0 is not a string.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_i32(&p, 0);
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(t.iface[0] == 0, "zero-length string rejected");

	// Length 201 is above the accepted bound.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_i32(&p, 201);
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(t.iface[0] == 0, "over-long string rejected");

	// Negative length is not a string.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_i32(&p, -1);
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(t.iface[0] == 0, "negative-length string rejected");

	// Non-ASCII code unit (0x7f) is rejected.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_i32(&p, 3);
	p.b[p.n++] = 'a'; p.b[p.n++] = 0;
	p.b[p.n++] = 0x7f; p.b[p.n++] = 0;
	p.b[p.n++] = 'c'; p.b[p.n++] = 0;
	p.b[p.n++] = 0; p.b[p.n++] = 0;
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(t.iface[0] == 0, "non-ASCII string rejected");

	// Missing NUL terminator: the declared length does not fit with its NUL.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_i32(&p, 3);
	p_raw(&p, "abc");                 // 4 + 6 bytes, no terminator/padding
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(t.iface[0] == 0, "unterminated string rejected");
}

static void test_bounds(void)
{
	struct binder_txn_text t;
	char longstr[151];
	struct parcel p;

	// A string cut mid-way by the captured length is ignored (no overread: the
	// allocation is exact, so ASAN traps a read past the end).
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.content.pm.IPackageManager");
	size_t cut = p.n - 5;             // inside the interface characters
	unsigned char *exact = malloc(cut);
	CHECK(exact != NULL, "exact-size allocation");
	if (exact) {
		memcpy(exact, p.b, cut);
		memset(&t, 0, sizeof t);
		binder_parse_parcel(exact, cut, &t);
		CHECK(t.iface[0] == 0, "string cut by the captured length is ignored");
		free(exact);
	}

	// More than six argument strings are capped.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.os.IServiceManager");
	for (int i = 0; i < 8; i++) {
		char s[16];
		snprintf(s, sizeof s, "svc%d", i);
		p_str16(&p, s);
	}
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(t.nstrs == BINDER_MAX_STRINGS, "argument strings capped at the maximum");
	CHECK(strcmp(t.strs[BINDER_MAX_STRINGS - 1], "svc5") == 0,
	      "last stored argument string");

	// A long interface is truncated to BINDER_STR_MAX - 1 characters.
	memset(longstr, 'x', 150);
	longstr[150] = 0;
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, longstr);
	memset(&t, 0, sizeof t);
	binder_parse_parcel(p.b, p.n, &t);
	CHECK(strlen(t.iface) == BINDER_STR_MAX - 1, "long interface truncated");
	CHECK(t.iface[BINDER_STR_MAX - 1] == 0, "truncated interface NUL-terminated");
}

static void test_names(void)
{
	char out[64];

	// BC command names: only the two transaction commands are named.
	CHECK(strcmp(binder_cmd_name(0x40406300u), "BC_TRANSACTION") == 0,
	      "BC_TRANSACTION name");
	CHECK(strcmp(binder_cmd_name(0x40486311u), "BC_TRANSACTION_SG") == 0,
	      "BC_TRANSACTION_SG name");
	CHECK(binder_cmd_name(0x40406301u) == NULL, "BC_REPLY has no transaction name");
	CHECK(binder_cmd_name(0) == NULL, "unknown command has no name");

	// TF_* flags.
	binder_flags_str(0, out, sizeof out);
	CHECK(strcmp(out, "0") == 0, "no flags render as 0");
	binder_flags_str(0x10, out, sizeof out);
	CHECK(strcmp(out, "TF_ACCEPT_FDS") == 0, "TF_ACCEPT_FDS rendered");
	binder_flags_str(0x11, out, sizeof out);
	CHECK(strcmp(out, "TF_ONE_WAY|TF_ACCEPT_FDS") == 0, "two flags joined");
	binder_flags_str(0x50, out, sizeof out);
	CHECK(strcmp(out, "TF_ACCEPT_FDS|TF_UPDATE_TXN") == 0, "flag bits 0x10 and 0x40");
	binder_flags_str(0x02, out, sizeof out);
	CHECK(strcmp(out, "0x2") == 0, "unknown flag bit renders as hex");
	binder_flags_str(0x12, out, sizeof out);
	CHECK(strcmp(out, "TF_ACCEPT_FDS|0x2") == 0, "known plus unknown flag bits");

	// Transaction-code names for the two stable interfaces only.
	CHECK(strcmp(binder_method_name("android.os.IServiceManager", 1), "getService") == 0,
	      "IServiceManager getService");
	CHECK(strcmp(binder_method_name("android.os.IServiceManager", 2), "checkService") == 0,
	      "IServiceManager checkService");
	CHECK(strcmp(binder_method_name("android.os.IServiceManager", 3), "addService") == 0,
	      "IServiceManager addService");
	CHECK(strcmp(binder_method_name("android.os.IServiceManager", 4), "listServices") == 0,
	      "IServiceManager listServices");
	CHECK(binder_method_name("android.os.IServiceManager", 9) == NULL,
	      "unknown IServiceManager code");
	CHECK(strcmp(binder_method_name("android.content.IContentProvider", 1), "query") == 0,
	      "IContentProvider query");
	CHECK(strcmp(binder_method_name("android.content.IContentProvider", 2), "getType") == 0,
	      "IContentProvider getType");
	CHECK(strcmp(binder_method_name("android.content.IContentProvider", 3), "insert") == 0,
	      "IContentProvider insert");
	CHECK(strcmp(binder_method_name("android.content.IContentProvider", 4), "delete") == 0,
	      "IContentProvider delete");
	CHECK(strcmp(binder_method_name("android.content.IContentProvider", 10), "update") == 0,
	      "IContentProvider update");
	CHECK(strcmp(binder_method_name("android.content.IContentProvider", 21), "call") == 0,
	      "IContentProvider call");
	CHECK(binder_method_name("android.content.IContentProvider", 5) == NULL,
	      "unknown IContentProvider code");
	CHECK(binder_method_name("android.content.pm.IPackageManager", 1) == NULL,
	      "no method table for other interfaces");
	CHECK(binder_method_name(NULL, 1) == NULL, "NULL interface has no method");
}

// Copy a jbuf into a NUL-terminated string (the serializer does not terminate).
static char *jstr(struct jbuf *j)
{
	char *s = malloc(j->len + 1);
	if (!s)
		return NULL;
	memcpy(s, j->b, j->len);
	s[j->len] = 0;
	return s;
}

// Structural JSON check: balanced braces/brackets, closed strings, no read past
// an escape. Values are not parsed.
static int json_balanced(const char *s)
{
	int brace = 0, bracket = 0, in_str = 0;
	for (const char *p = s; *p; p++) {
		if (in_str) {
			if (*p == '\\') {
				if (!p[1])
					return 0;
				p++;
			} else if (*p == '"') {
				in_str = 0;
			}
			continue;
		}
		switch (*p) {
		case '"': in_str = 1; break;
		case '{': brace++; break;
		case '}': if (--brace < 0) return 0; break;
		case '[': bracket++; break;
		case ']': if (--bracket < 0) return 0; break;
		}
	}
	return !in_str && brace == 0 && bracket == 0;
}

static void expect_exact(struct jbuf *j, const char *want, const char *msg)
{
	char *got = jstr(j);
	CHECK(got != NULL, "json output allocated");
	if (!got)
		return;
	CHECK(strcmp(got, want) == 0, msg);
	if (strcmp(got, want) != 0)
		printf("    got: %s\n   want: %s\n", got, want);
	free(got);
}

static void expect_valid(struct jbuf *j, const char *msg)
{
	char *body = jstr(j);
	if (!body) {
		CHECK(0, msg);
		return;
	}
	char *wrapped = malloc(strlen(body) + 4);
	CHECK(wrapped != NULL, "json wrapper allocated");
	if (wrapped) {
		sprintf(wrapped, "{%s}", body);
		CHECK(json_balanced(wrapped), msg);
		free(wrapped);
	}
	free(body);
}

static void test_emit_json(void)
{
	struct jbuf j = {0};
	struct parcel p;
	struct binder_txn_view v;

	// Full object: command, metadata, interface, method and argument strings.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.content.IContentProvider");
	p_str16(&p, "settings");
	p_str16(&p, "GET_secure");
	p_str16(&p, "adb_enabled");
	v.cmd = 0x40406300u;
	v.handle = 3;
	v.code = 1;
	v.flags = 0x10;
	v.data_size = 100;
	v.data = p.b;
	v.copied = p.n;
	j.len = 0;
	binder_emit_json(&j, &v);
	expect_exact(&j,
		"\"binder\":{\"cmd\":\"BC_TRANSACTION\",\"handle\":3,\"code\":1,"
		"\"flags\":\"TF_ACCEPT_FDS\",\"data_size\":100,"
		"\"interface\":\"android.content.IContentProvider\","
		"\"method\":\"query\","
		"\"strings\":[\"settings\",\"GET_secure\",\"adb_enabled\"]}",
		"full binder object");
	CHECK(j.b[0] == '"', "binder member has no leading comma");
	expect_valid(&j, "full binder object is valid JSON");

	// Interface without strings and without a stable method code.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "android.os.IServiceManager");
	v.handle = 4;
	v.code = 9;
	v.flags = 0x01;
	v.data_size = 8;
	v.data = p.b;
	v.copied = p.n;
	j.len = 0;
	binder_emit_json(&j, &v);
	expect_exact(&j,
		"\"binder\":{\"cmd\":\"BC_TRANSACTION\",\"handle\":4,\"code\":9,"
		"\"flags\":\"TF_ONE_WAY\",\"data_size\":8,"
		"\"interface\":\"android.os.IServiceManager\"}",
		"binder object without strings or method");
	expect_valid(&j, "string-less binder object is valid JSON");

	// No captured payload: metadata only, no interface/method/strings keys.
	v.cmd = 0x40486311u;
	v.handle = 0;
	v.code = 5;
	v.flags = 0;
	v.data_size = 0;
	v.data = NULL;
	v.copied = 0;
	j.len = 0;
	binder_emit_json(&j, &v);
	expect_exact(&j,
		"\"binder\":{\"cmd\":\"BC_TRANSACTION_SG\",\"handle\":0,\"code\":5,"
		"\"flags\":\"0\",\"data_size\":0}",
		"binder object from metadata only");
	expect_valid(&j, "metadata-only binder object is valid JSON");

	// Quotes and backslashes are escaped in both the interface and strings.
	memset(&p, 0, sizeof p);
	p_header(&p, 0);
	p_str16(&p, "a\"b\\c");
	p_str16(&p, "q\"x\\y");
	v.cmd = 0x40406300u;
	v.code = 0;
	v.flags = 0x20;
	v.data = p.b;
	v.copied = p.n;
	j.len = 0;
	binder_emit_json(&j, &v);
	{
		char *got = jstr(&j);
		CHECK(got != NULL, "escaped output allocated");
		if (got) {
			CHECK(strstr(got, "\"interface\":\"a\\\"b\\\\c\"") != NULL,
			      "interface quotes and backslashes escaped");
			CHECK(strstr(got, "\"strings\":[\"q\\\"x\\\\y\"]") != NULL,
			      "argument quotes and backslashes escaped");
			free(got);
		}
	}
	expect_valid(&j, "escaped binder object is valid JSON");

	free(j.b);
}

int main(void)
{
	test_parcel_shapes();
	test_rejected_shapes();
	test_bounds();
	test_names();
	test_emit_json();

	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
