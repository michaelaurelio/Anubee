// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for anubee mod analyzers (Phase 1: proc-event).
// No libbpf deps — host-testable. Builds on the shared jb_* serializer.
// Each function builds one bare JSON object into j (no trailing newline/framing);
// the caller wraps it in anubee_sink_emit or uses j.b/j.len directly in tests.
#ifndef __ANUBEE_MOD_EMIT_H
#define __ANUBEE_MOD_EMIT_H

struct jbuf;             // common/emit.h
struct spawn_event;      // modules/mod_events.h
struct proc_exit_event;  // modules/mod_events.h
struct execve_event;     // modules/mod_events.h
struct prop_event;       // modules/mod_events.h
struct file_access_event; // modules/mod_events.h
struct massdelete_detect_event; // modules/mod_events.h
struct exfil_detect_event; // modules/mod_events.h
struct accessibility_detect_event; // modules/mod_events.h
struct fileless_detect_event; // modules/mod_events.h
struct screencapture_detect_event; // modules/mod_events.h
struct binder_api_event;          // modules/mod_events.h
struct dexload_detect_event;      // modules/mod_events.h

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

// {"type":"massdelete_detect","pid":N,"comm":"..","touch_count":N,
//  "distinct_estimate":N,"window_ms":N,"sample_path":"..",
//  "manage_external_storage":true|false|null[,"paths":["..",...]]}
// distinct_estimate: caller-computed via burst_distinct_count (keeps this
// builder free of that logic). Field name "distinct_estimate" retained for schema stability;
// the value is exact as of this branch, not an FNV-hash approximation.
// manage_ext_storage is tri-state: 1 = granted
// -> true, 0 = checked and not granted -> false, negative = unknown
// (package unresolved, never checked) -> null. paths: only present when
// verbose is set; exactly touch_count entries (complete, not a sample --
// RING_LEN > THRESHOLD guarantees the ring never wraps before emission).
void mod_emit_massdelete_detect(struct jbuf *j, const struct massdelete_detect_event *e,
                                int distinct_estimate, int manage_ext_storage, int verbose);

// {"type":"exfil_detect","pid":N,"comm":"..","bytes_sent":N,"window_ms":N,
//  "sample_path":"..","dest":".."|null
//  [,"sensitive_paths":["..",...],"sensitive_path_count":N,"paths_truncated":true|false]}
// dest_str: caller-decoded via decode_sockaddr (common/decode.h) -- keeps this
// builder free of that logic. It is the kernel-side peer of the socket the
// threshold-tripping send went to; NULL or empty -> JSON null (defensive --
// only sends to an outbound IPv4/IPv6 peer are counted, so an alert has one). sensitive_paths/
// sensitive_path_count/paths_truncated: only present when verbose is set.
// sensitive_paths always has min(sensitive_path_count, EXFIL_DETECT_RING_LEN)
// entries -- the ring only ever physically holds RING_LEN slots.
// sensitive_path_count is the true total opened this window (keeps counting
// past RING_LEN once wrapped). paths_truncated:true means
// sensitive_path_count > RING_LEN -- the list is a lower bound, not a
// guarantee (unlike massdelete_detect's paths, which are always complete).
void mod_emit_exfil_detect(struct jbuf *j, const struct exfil_detect_event *e,
                           const char *dest_str, int verbose);

// {"type":"accessibility_detect","pid":N,"ts_ns":N,"comm":"..","category":"screen_read",
//  "method":"getWindows"|null,"code":N,"granted":true|false|null}
// One record per (process, abuse category), on the first
// IAccessibilityServiceConnection call in that category
// (accessibility_detect_classify.h). granted mirrors massdelete_detect's
// manage_ext_storage tri-state: 1 -> true, 0 -> false, negative -> null.
void mod_emit_accessibility_detect(struct jbuf *j, const struct accessibility_detect_event *e,
                                   const char *category, const char *method, int granted);

// {"type":"fileless_detect","pid":N,"ts_ns":N,"comm":"..",
//  "kind":"anon_exec_mmap|mprotect_exec|memfd_exec","start":"0x..","size":N,
//  "anon_name":"..","content":"elf|zero|data"|null,
//  "saved":{"file":"..","sha256":"..","size":N}|null}
// anon_name is the region's (or memfd's) name as the kernel holds it, "" if
// unnamed. content classifies the region's first bytes when they could be
// read; saved is the copy taken through /proc/<pid>/mem (or the memfd).
void mod_emit_fileless_detect(struct jbuf *j, const struct fileless_detect_event *e,
                              const char *kind, const char *content,
                              const char *saved, const char *sha256, long long size);

// {"type":"screencapture_detect","pid":N,"ts_ns":N,"comm":"..",
//  "stage":"fgs_declared|projection_start|virtual_display",
//  "interface":".."|null,"method":".."|null,"code":N|null}
// One per (process, stage) -- fgs_declared again per new session. Binder
// stages carry the decoded call; fgs_declared (dumpsys poll) has nulls.
void mod_emit_screencapture_detect(struct jbuf *j, const struct screencapture_detect_event *e,
                                   const char *stage, const char *iface, const char *method);

// {"type":"dexload_detect","pid":N,"ts_ns":N,"comm":"..","stage":"drop|load|delete",
//  "kind":"dex|cdex|zip|elf","path":".."|null,"ino":N,"exec":bool|null,
//  "after_drop_ms":N|null,"saved":{"file":"..","sha256":"..","size":N}|null}
// exec is set on load only; after_drop_ms < 0 and saved == NULL print null.
// stage "memload" (a DEX ART holds in anonymous memory) adds
// "start":"0x..","region_size":N after ino (0); path is the file ART
// extracted it from, or null for a DEX loaded from memory.
void mod_emit_dexload_detect(struct jbuf *j, const struct dexload_detect_event *e,
                             const char *kind, const char *path, long long after_drop_ms,
                             const char *saved, const char *sha256, long long size);

// {"type":"binder_api","pid":N,"tid":N,"ts_ns":N,"comm":"..","interface":".."|null,
//  "method":".."|null,"code":N,"oneway":bool} -- first call of (interface, method)
// by this process. iface NULL = token not decodable; method NULL = code not in
// the device's framework stubs (app-private or vendor AIDL, or a non-AIDL call).
// cp (may be NULL): IContentProvider detail -> adds "uri":".." or
// "call":{"authority":..,"method":..,"arg":..|null}.
struct binder_cp_detail;
void mod_emit_binder_api(struct jbuf *j, const struct binder_api_event *e,
                         const char *iface, const char *method,
                         const struct binder_cp_detail *cp);

// {"type":"perm_change","ts_ns":N,"package":"..","category":"..","name":"..",
//  "change":"baseline|granted|revoked|changed","old":".."|null,"new":".."|null}
// `key` is a perm_watch_parse.h fact key; category/name are split from it
// (special-access keys have no prefix, so name == category). Built in
// userspace (no BPF event), so it takes its fields directly.
void mod_emit_perm_change(struct jbuf *j, unsigned long long ts_ns, const char *pkg,
                          const char *key, const char *change,
                          const char *old_val, const char *new_val);

#endif /* __ANUBEE_MOD_EMIT_H */
