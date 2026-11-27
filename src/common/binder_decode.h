/* binder_decode.h
 *
 * Pure userspace decoding of a captured binder transaction payload.
 *
 * The syscalls BPF program copies the first bytes of the Parcel data buffer of a
 * BC_TRANSACTION/BC_TRANSACTION_SG. The buffer holds int32 transport fields
 * followed by String16 values: the receiver's interface token and the call
 * arguments. These helpers turn those bytes into the interface name, the
 * argument strings and display names for the BC command, TF flags and the two
 * transaction-code tables whose numbers are stable ABI. No I/O, no allocation:
 * host-testable on its own.
 */
#ifndef __ANUBEE_BINDER_DECODE_H
#define __ANUBEE_BINDER_DECODE_H

#include <stddef.h>

#define BINDER_MAX_STRINGS 6
#define BINDER_STR_MAX     96

struct binder_txn_text {
	char iface[BINDER_STR_MAX];              /* interface token, "" if none */
	char strs[BINDER_MAX_STRINGS][BINDER_STR_MAX];  /* argument strings */
	int nstrs;                               /* valid entries in strs[] */
};

/* Walk a captured Parcel buffer (data, n bytes) at 4-byte aligned offsets and
 * copy the first accepted String16 into iface, the next ones into strs[] (at
 * most BINDER_MAX_STRINGS, each truncated to BINDER_STR_MAX - 1 characters).
 * A String16 is accepted when its length is 1..200, it fits entirely in the
 * captured bytes, every code unit is printable ASCII and it is NUL-terminated.
 * The output is always fully initialised. */
void binder_parse_parcel(const unsigned char *data, size_t n,
			 struct binder_txn_text *out);

/* Name of a transaction command (BC_TRANSACTION / BC_TRANSACTION_SG), or NULL. */
const char *binder_cmd_name(unsigned cmd);

/* Render TF_* flags as "TF_ONE_WAY|TF_ACCEPT_FDS"; "0" when none; bits without
 * a name are appended as hex. */
void binder_flags_str(unsigned flags, char *out, size_t outsz);

/* Name of a transaction code for the interfaces whose codes are stable ABI
 * (android.os.IServiceManager, android.content.IContentProvider), or NULL. */
const char *binder_method_name(const char *iface, unsigned code);

struct jbuf;

/* One captured transaction in the shape the JSON emitter needs, decoupled from
 * the BPF record layout. data holds copied valid bytes. */
struct binder_txn_view {
	unsigned cmd;
	unsigned handle;
	unsigned code;
	unsigned flags;
	unsigned long long data_size;
	const unsigned char *data;
	size_t copied;
};

/* Append the "binder":{...} member to j (no leading comma; the caller adds one
 * when the record already has members). interface/strings appear only when
 * non-empty, method only for the two interfaces with a stable code table. */
void binder_emit_json(struct jbuf *j, const struct binder_txn_view *txn);

#endif /* __ANUBEE_BINDER_DECODE_H */
