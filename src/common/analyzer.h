// SPDX-License-Identifier: GPL-2.0
// ares_analyzer_t — interface every `ares mod <name>` analyzer implements.
// The dispatcher (src/modules/mod.c) owns arg-parse, uid resolve, sink, stop
// handler, app launch, ring-poll, and teardown order. Each analyzer owns ONLY
// its own BPF skeleton + event semantics.
#ifndef __ARES_ANALYZER_H
#define __ARES_ANALYZER_H

struct ares_sink;   // common/emit.h — full def needed by callers that open a sink
struct ring_buffer; // libbpf — full def needed to poll
struct target_args; // common/engine_args.h — full def at setup() call site

// Console/sink context the dispatcher builds once and hands to setup(); the
// analyzer stores the pointer and passes it as the ring_buffer sample-fn ctx.
struct ares_mod_ctx {
    struct ares_sink *sink;  // NULL when no -o (console-only mode)
    int quiet;               // suppress human-readable console lines
    int verbose;             // extra console detail
    const struct target_args *tgt; // NULL → launch/UID mode; n>0 → PID attach
    const char *pkg;          // launched package (-P), or best-effort resolved
                              // in -p mode via ares_resolve_pkg_from_pid; NULL
                              // if unknown. Used by file-access classification.
};

// One entry in the analyzer registry.
typedef struct {
    const char *name;        // dispatch token; also the "mod:<name>" key in capabilities.c
    const char *description; // shown in `ares mod --help`
    // Open + load the analyzer's OWN BPF skeleton, arm `uid` into its target_uids
    // map, attach programs, and create a ring_buffer whose sample callback is the
    // analyzer's static handle_event with ctx set to mc. Returns the ring_buffer*
    // for the dispatcher to poll, or NULL on any setup failure (analyzer cleans up
    // before returning NULL).
    struct ring_buffer *(*setup)(int uid, struct ares_mod_ctx *mc);
    // Destroy rb, skeleton, and any bpf_link*s. Called after the poll loop exits.
    void (*teardown)(void);
    // Print tally / RASP table to stdout at session end. May be NULL.
    void (*print_summary)(void);
    // Emit one {"type":"<name>_summary",...} record to the sink, mirroring
    // print_summary's tally into the file. Called only when a sink is open
    // (sink->f != NULL). May be NULL.
    void (*emit_summary)(struct ares_sink *sink);
    // Sum this analyzer's own `dropped` BPF map (mod drop-telemetry parity). Read
    // the fd BEFORE teardown() destroys the skeleton — call this first. May be
    // NULL only for an analyzer that genuinely can't drop events (none today).
    unsigned long long (*drops)(void);
} ares_analyzer_t;

// Defined in each analyzer's .c; the dispatcher references them by pointer in
// the registry array (src/modules/mod.c).
extern const ares_analyzer_t analyzer_proc_event;
extern const ares_analyzer_t analyzer_execve;
extern const ares_analyzer_t analyzer_prop_read;
extern const ares_analyzer_t analyzer_file_access;
extern const ares_analyzer_t analyzer_massdelete_detect;
extern const ares_analyzer_t analyzer_exfil_detect;
extern const ares_analyzer_t analyzer_accessibility_detect;
extern const ares_analyzer_t analyzer_fileless_detect;
extern const ares_analyzer_t analyzer_screencapture_detect;

#endif /* __ARES_ANALYZER_H */
