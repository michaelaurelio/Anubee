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

// {"type":"prop","op":"get|find|scan|read","pid":N,"tid":N,"comm":"..",
//  "name":"..","value":"..","is_ret":N,"found":N}
void mod_emit_prop(struct jbuf *j, const struct prop_event *e);

#endif /* __ARES_MOD_EMIT_H */
