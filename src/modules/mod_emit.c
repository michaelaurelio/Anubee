// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for ares mod analyzers (no libbpf/skeleton
// deps, so the host test can link them). Built on the shared serializer + schema.
#include <linux/types.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "modules/mod_events.h"
#include "modules/file_access_classify.h"

void mod_emit_spawn(struct jbuf *j, const struct spawn_event *e)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_SPAWN)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"ts_ns\":");      jb_u64(j, e->ts_ns);
    jb_s(j, ",\"child_pid\":"); jb_u64(j, e->child_pid);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    jb_c(j, '}');
}

void mod_emit_proc_exit(struct jbuf *j, const struct proc_exit_event *e)
{
    int sig    = e->exit_code & 0x7f;
    int status = (e->exit_code >> 8) & 0xff;

    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_PROC_EXIT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"ts_ns\":");      jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    if (sig)
        { jb_s(j, ",\"signal\":"); jb_u64(j, sig); }
    else
        { jb_s(j, ",\"exit_status\":"); jb_u64(j, status); }
    jb_c(j, '}');
}

// syms: resolved symbol strings for each frame (NULL or syms[i]==NULL/"" → omit symbol field).
// Caller (execve.c) resolves via sym_resolve; passing NULL produces addr-only output.
void mod_emit_execve(struct jbuf *j, const struct execve_event *e, const char *const *syms)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_EXECVE)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");         jb_u64(j, e->h.tid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"filename\":\"");  jb_esc(j, e->filename); jb_c(j, '"');
    jb_s(j, ",\"argc\":");        jb_u64(j, e->argc);
    jb_s(j, ",\"argv\":[");
    for (int i = 0; i < (int)e->argc && i < MAX_ARGV_ENTRIES; i++) {
        if (i) jb_c(j, ',');
        jb_c(j, '"'); jb_esc(j, e->argv[i]); jb_c(j, '"');
    }
    jb_c(j, ']');
    jb_s(j, ",\"backtrace\":[");
    for (int i = 0, first = 1; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
        if (e->call_stack[i] == 0) break;
        if (!first) jb_c(j, ',');
        first = 0;
        jb_s(j, "{\"frame\":");  jb_u64(j, i);
        jb_s(j, ",\"addr\":\""); jb_hex(j, e->call_stack[i]); jb_c(j, '"');
        if (syms && syms[i] && syms[i][0]) {
            jb_s(j, ",\"symbol\":\""); jb_esc(j, syms[i]); jb_c(j, '"');
        }
        jb_c(j, '}');
    }
    jb_c(j, ']');
    jb_c(j, '}');
}

void mod_emit_prop(struct jbuf *j, const struct prop_event *e)
{
    const char *op;
    switch (e->h.type) {
    case MOD_EV_PROP_GET:  op = "get";     break;
    case MOD_EV_PROP_FIND: op = "find";    break;
    case MOD_EV_PROP_SCAN: op = "scan";    break;
    case MOD_EV_PROP_READ: op = "read";    break;
    default:               op = "unknown"; break;
    }
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");    jb_s(j, trace_type_name(TRACE_PROP)); jb_c(j, '"');
    jb_s(j, ",\"op\":\"");     jb_s(j, op); jb_c(j, '"');
    jb_s(j, ",\"pid\":");      jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");      jb_u64(j, e->h.tid);
    jb_s(j, ",\"ts_ns\":");    jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");   jb_esc(j, e->comm); jb_c(j, '"');
    // SCAN is a marker event only (no name/value captured); omit the empty fields.
    if (e->h.type != MOD_EV_PROP_SCAN) {
        jb_s(j, ",\"name\":\"");   jb_esc(j, e->name); jb_c(j, '"');
        jb_s(j, ",\"value\":\"");  jb_esc(j, e->value); jb_c(j, '"');
        jb_s(j, ",\"is_ret\":");   jb_u64(j, e->is_ret);
        jb_s(j, ",\"found\":");    jb_u64(j, e->found);
    }
    jb_c(j, '}');
}

void mod_emit_file_access(struct jbuf *j, const struct file_access_event *e,
                           unsigned categories, const char *const *flag_strs, int n_flags)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_FILE_ACCESS)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");        jb_u64(j, e->h.tid);
    jb_s(j, ",\"ts_ns\":");      jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"path\":\"");     jb_esc(j, e->path); jb_c(j, '"');

    jb_s(j, ",\"flags\":[");
    for (int i = 0; i < n_flags; i++) {
        if (i) jb_c(j, ',');
        jb_c(j, '"'); jb_s(j, flag_strs[i]); jb_c(j, '"');
    }
    jb_c(j, ']');

    jb_s(j, ",\"categories\":[");
    int first = 1;
    struct { unsigned bit; const char *name; } tags[] = {
        { FA_EXTERNAL_STORAGE,   "external_storage"   },
        { FA_MEDIA_SUBDIR,       "media_subdir"       },
        { FA_CREDENTIAL_PATTERN, "credential_pattern" },
        { FA_FOREIGN_APP_DIR,    "foreign_app_dir"    },
        { FA_UNKNOWN_SELF,       "unknown_self"       },
    };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        if (!(categories & tags[i].bit)) continue;
        if (!first) jb_c(j, ',');
        first = 0;
        jb_c(j, '"'); jb_s(j, tags[i].name); jb_c(j, '"');
    }
    jb_c(j, ']');

    jb_c(j, '}');
}

void mod_emit_massdelete_detect(struct jbuf *j, const struct massdelete_detect_event *e,
                                int distinct_estimate, int manage_ext_storage, int verbose)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");         jb_s(j, trace_type_name(TRACE_MASSDELETE_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");           jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");         jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");        jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"touch_count\":");   jb_u64(j, e->touch_count);
    jb_s(j, ",\"distinct_estimate\":"); jb_u64(j, (unsigned long long)distinct_estimate);
    jb_s(j, ",\"window_ms\":");     jb_u64(j, e->window_ms);
    jb_s(j, ",\"sample_path\":\""); jb_esc(j, e->sample_path); jb_c(j, '"');
    jb_s(j, ",\"manage_external_storage\":");
    if (manage_ext_storage < 0)
        jb_s(j, "null");
    else
        jb_s(j, manage_ext_storage ? "true" : "false");
    if (verbose) {
        jb_s(j, ",\"paths\":[");
        for (int i = 0; i < (int)e->touch_count && i < MASSDELETE_DETECT_RING_LEN; i++) {
            if (i) jb_c(j, ',');
            jb_c(j, '"'); jb_esc(j, e->paths[i]); jb_c(j, '"');
        }
        jb_c(j, ']');
    }
    jb_c(j, '}');
}

void mod_emit_exfil_detect(struct jbuf *j, const struct exfil_detect_event *e,
                           const char *dest_str, int verbose)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");         jb_s(j, trace_type_name(TRACE_EXFIL_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");           jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");         jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");        jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"bytes_sent\":");    jb_u64(j, e->bytes_sent);
    jb_s(j, ",\"window_ms\":");     jb_u64(j, e->window_ms);
    jb_s(j, ",\"sample_path\":\""); jb_esc(j, e->sample_path); jb_c(j, '"');
    jb_s(j, ",\"dest\":");
    if (dest_str && dest_str[0]) {
        jb_c(j, '"'); jb_esc(j, dest_str); jb_c(j, '"');
    } else {
        jb_s(j, "null");
    }
    if (verbose) {
        int n = (int)e->sensitive_path_count;
        if (n > EXFIL_DETECT_RING_LEN) n = EXFIL_DETECT_RING_LEN;
        jb_s(j, ",\"sensitive_paths\":[");
        for (int i = 0; i < n; i++) {
            if (i) jb_c(j, ',');
            jb_c(j, '"'); jb_esc(j, e->sensitive_paths[i]); jb_c(j, '"');
        }
        jb_c(j, ']');
        jb_s(j, ",\"sensitive_path_count\":"); jb_u64(j, e->sensitive_path_count);
        jb_s(j, ",\"paths_truncated\":");      jb_s(j, e->paths_truncated ? "true" : "false");
    }
    jb_c(j, '}');
}

void mod_emit_accessibility_detect(struct jbuf *j, const struct accessibility_detect_event *e, int granted)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_ACCESSIBILITY_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"touch_count\":"); jb_u64(j, e->touch_count);
    jb_s(j, ",\"window_ms\":");   jb_u64(j, e->window_ms);
    jb_s(j, ",\"granted\":");
    if (granted < 0)
        jb_s(j, "null");
    else
        jb_s(j, granted ? "true" : "false");
    jb_c(j, '}');
}

void mod_emit_fileless_detect(struct jbuf *j, const struct fileless_detect_event *e)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_FILELESS_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"start\":\"");     jb_hex(j, e->start); jb_c(j, '"');
    jb_s(j, ",\"size\":");        jb_u64(j, e->size);
    jb_s(j, ",\"anon_name\":\""); jb_esc(j, e->anon_name); jb_c(j, '"');
    jb_c(j, '}');
}

void mod_emit_screencapture_detect(struct jbuf *j, const struct screencapture_detect_event *e)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_SCREENCAPTURE_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"binder_calls_context\":"); jb_u64(j, e->binder_calls_context);
    jb_c(j, '}');
}
