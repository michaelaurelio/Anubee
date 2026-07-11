// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares mod analyzers (Phase 1: proc-event).
// No libbpf deps — host-testable. Builds on the shared jb_* serializer.
// Each function builds one bare JSON object into j (no trailing newline/framing);
// the caller wraps it in ares_sink_emit or uses j.b/j.len directly in tests.
#ifndef __ARES_MOD_EMIT_H
#define __ARES_MOD_EMIT_H

struct jbuf;             // common/emit.h
struct spawn_event;      // modules/mod_events.h
struct proc_exit_event;  // modules/mod_events.h
struct execve_event;     // modules/mod_events.h
struct prop_event;       // modules/mod_events.h
struct file_access_event; // modules/mod_events.h
struct ransomware_burst_event; // modules/mod_events.h
struct exfil_burst_event; // modules/mod_events.h
struct a11y_abuse_event; // modules/mod_events.h

// {"type":"spawn","pid":N,"tid":N,"child_pid":N,"comm":"..."}
void mod_emit_spawn(struct jbuf *j, const struct spawn_event *e);

// {"type":"proc_exit","pid":N,"tid":N,"comm":"...","exit_status":N}
// or {"type":"proc_exit","pid":N,"tid":N,"comm":"...","signal":N} when killed by signal.
// sig = exit_code & 0x7f; status = (exit_code >> 8) & 0xff; sig wins if nonzero.
void mod_emit_proc_exit(struct jbuf *j, const struct proc_exit_event *e);

// {"type":"execve","pid":N,"tid":N,"comm":"..","filename":"..","argc":N,
//  "argv":["..",..],"backtrace":[{"frame":N,"addr":"0x..","symbol":".."},..]}
// syms: per-frame resolved strings (NULL → addr-only; syms[i]==NULL/"" → omit that frame's symbol).
void mod_emit_execve(struct jbuf *j, const struct execve_event *e, const char *const *syms);

// {"type":"prop","op":"get|find|read","pid":N,"tid":N,"comm":"..",
//  "name":"..","value":"..","is_ret":N,"found":N}
// SCAN: {"type":"prop","op":"scan","pid":N,"tid":N,"comm":".."} — no name/value/is_ret/found
//  (SCAN is a marker event with no property name captured).
void mod_emit_prop(struct jbuf *j, const struct prop_event *e);

// {"type":"file_access","pid":N,"tid":N,"comm":"..","path":"..",
//  "flags":["O_RDONLY"|...],
//  "categories":["external_storage"|"media_subdir"|"credential_pattern"|
//                "foreign_app_dir"|"unknown_self",...]}
// categories: bitmask of FA_* (modules/file_access_classify.h). flag_strs/n_flags:
// pre-decoded via file_access_decode_flags (caller decodes; keeps this builder
// free of the flags bit-layout).
void mod_emit_file_access(struct jbuf *j, const struct file_access_event *e,
                           unsigned categories, const char *const *flag_strs, int n_flags);

// {"type":"ransomware_burst","pid":N,"comm":"..","touch_count":N,
//  "distinct_estimate":N,"window_ms":N,"sample_path":"..",
//  "manage_external_storage":true|false|null}
// distinct_estimate: caller-computed via burst_distinct_count (keeps this
// builder free of that logic). manage_ext_storage is tri-state: 1 = granted
// -> true, 0 = checked and not granted -> false, negative = unknown
// (package unresolved, never checked) -> null.
void mod_emit_ransomware_burst(struct jbuf *j, const struct ransomware_burst_event *e,
                                int distinct_estimate, int manage_ext_storage);

// {"type":"exfil_burst","pid":N,"comm":"..","bytes_sent":N,"window_ms":N,
//  "sample_path":"..","dest":".."|null}
// dest_str: caller-decoded via decode_sockaddr (common/decode.h) -- keeps this
// builder free of that logic, same pattern as ransomware_burst's
// distinct_estimate. NULL or empty -> JSON null (no connect() observed before
// the byte threshold tripped, e.g. all volume went via a pre-attach socket's
// sendto).
void mod_emit_exfil_burst(struct jbuf *j, const struct exfil_burst_event *e,
                           const char *dest_str);

// {"type":"a11y_abuse","pid":N,"comm":"..","touch_count":N,"window_ms":N,
//  "granted":true|false|null}
// granted mirrors ransomware_burst's manage_ext_storage tri-state: 1 -> true,
// 0 -> false, negative (unknown/unchecked) -> null. No "severity" field --
// consumers derive it from touch_count/granted the same way classify_a11y()
// does, matching ransomware_burst/exfil_burst's convention of exposing raw
// fields rather than a baked-in classification string.
void mod_emit_a11y_abuse(struct jbuf *j, const struct a11y_abuse_event *e, int granted);

#endif /* __ARES_MOD_EMIT_H */
