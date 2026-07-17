// SPDX-License-Identifier: GPL-2.0
// Shared trace event schema: the canonical event header and the `type`
// discriminator used by every engine's structured output. Source-shared into
// both BPF objects (after vmlinux.h) and userspace loaders, so it must NOT pull
// <linux/types.h> or libc headers (would clash with vmlinux.h) — same rule as
// src/correlate/correlate.h.
#ifndef __ANUBEE_TRACE_SCHEMA_H
#define __ANUBEE_TRACE_SCHEMA_H

// Canonical per-event header. Replaces the byte-identical struct event_header
// (funcs) and struct corr_event_header (correlate).
struct trace_event_header {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 _pad;
};

// The single discriminator vocabulary. Host-side anubee-mcp keys ingest on the
// string form (see trace_type_name). Not compiled into BPF objects (vmlinux.h
// defines conflicting enum members such as TRACE_STACK).
#ifndef __bpf__
enum trace_event_type {
    TRACE_CALL = 1,   // native function entry (funcs)
    TRACE_RETURN,     // native function return (funcs)
    TRACE_SYSCALL,    // syscall record (syscalls / correlate)
    TRACE_LIB,        // library mmap  ("lib"   — matches anubee_libtrace_emit_lib output)
    TRACE_UNLIB,      // library munmap ("unlib" — matches anubee_libtrace_emit_unlib output)
    TRACE_SPAWN,      // process fork
    TRACE_PROC_EXIT,  // process exit
    TRACE_EXECVE,     // execve
    TRACE_PROP,       // system-property API hook
    TRACE_STACK,      // stack snapshot sidecar
    TRACE_FUNC,       // correlate span-open (probed function entered)
    TRACE_FILE_ACCESS, // sensitive file open (mod file-access)
    TRACE_MASSDELETE_DETECT, // rename/unlink burst (mod massdelete-detect)
    TRACE_DUMP,        // rebuilt-module manifest record (dump, SYM1 Phase 3)
    TRACE_EXFIL_DETECT, // sensitive-read-then-network-burst (mod exfil-detect)
    TRACE_ACCESSIBILITY_DETECT, // binder-transaction burst to system_server (mod accessibility-detect)
    TRACE_FILELESS_DETECT, // anonymous executable mmap, non-ART (mod fileless-detect)
    TRACE_SCREENCAPTURE_DETECT, // active MediaProjection screen-capture session (mod screencapture-detect)
    TRACE_MODCMP,      // module memory-vs-disk comparison (dump --check)
};

// Map a trace_event_type to its stable string name; "unknown" if out of range.
// Defined in trace_schema.c.
const char *trace_type_name(unsigned type);
#endif /* __bpf__ */

#endif /* __ANUBEE_TRACE_SCHEMA_H */
