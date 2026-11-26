// SPDX-License-Identifier: GPL-2.0
// Pure structured-record builders for anubee mod analyzers (no libbpf/skeleton
// deps, so the host test can link them). Built on the shared serializer + schema.
#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include "common/emit.h"
#include "common/trace_schema.h"
#include "modules/mod_events.h"
#include "modules/file_access_classify.h"
#include "modules/perm_watch_parse.h"
#include "modules/binder_api_parse.h"
#include "modules/sysret_pend.h"

// ,"result":N[,"error":"ENAME"] or ,"result":null; nothing when r is NULL.
static void emit_result(struct jbuf *j, const struct sys_result *r)
{
    if (!r) return;
    if (!r->known) { jb_s(j, ",\"result\":null"); return; }
    jb_s(j, ",\"result\":"); jb_i64(j, r->ret);
    const char *name = sys_errno_name(r->ret);
    if (name) { jb_s(j, ",\"error\":\""); jb_s(j, name); jb_c(j, '"'); }
}

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
void mod_emit_execve(struct jbuf *j, const struct execve_event *e, const char *const *syms,
                     const char *flags, const struct sys_result *r)
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
    jb_s(j, ",\"argv_truncated\":"); jb_s(j, e->truncated ? "true" : "false");
    jb_s(j, ",\"flags\":[");
    // flags: "a,b,c" -> ["a","b","c"]
    for (const char *p = flags ? flags : ""; *p; ) {
        const char *c = strchr(p, ',');
        size_t n = c ? (size_t)(c - p) : strlen(p);
        if (p != flags) jb_c(j, ',');
        char w[32];
        snprintf(w, sizeof w, "%.*s", (int)(n < sizeof w ? n : sizeof w - 1), p);
        jb_c(j, '"'); jb_esc(j, w); jb_c(j, '"');
        p += n;
        if (*p == ',') p++;
    }
    jb_c(j, ']');
    emit_result(j, r);
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
                           unsigned categories, const char *const *flag_strs, int n_flags,
                           const struct sys_result *r)
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
        { FA_OWN_APP_DIR,        "own_app_dir"        },
        { FA_PROC_SELF,          "proc_self"          },
        { FA_PROC_OTHER,         "proc_other_process" },
        { FA_PROC_SYSTEM,        "proc_system"        },
    };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        if (!(categories & tags[i].bit)) continue;
        if (!first) jb_c(j, ',');
        first = 0;
        jb_c(j, '"'); jb_s(j, tags[i].name); jb_c(j, '"');
    }
    jb_c(j, ']');
    emit_result(j, r);

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
        jb_s(j, ",\"sensitive_paths\":[");
        int emitted = 0;
        for (int i = 0; i < EXFIL_DETECT_RING_LEN; i++) {
            if (e->sensitive_paths[i][0] == '\0') continue; // blanked: not within EXFIL_RECENT_NS of the burst
            if (emitted) jb_c(j, ',');
            jb_c(j, '"'); jb_esc(j, e->sensitive_paths[i]); jb_c(j, '"');
            emitted++;
        }
        jb_c(j, ']');
        jb_s(j, ",\"sensitive_path_count\":"); jb_u64(j, e->sensitive_path_count);
        jb_s(j, ",\"paths_truncated\":");      jb_s(j, e->paths_truncated ? "true" : "false");
    }
    jb_c(j, '}');
}

static void jb_str_or_null(struct jbuf *j, const char *s)
{
    if (!s) { jb_s(j, "null"); return; }
    jb_c(j, '"'); jb_esc(j, s); jb_c(j, '"');
}

void mod_emit_accessibility_detect(struct jbuf *j, const struct accessibility_detect_event *e,
                                   const char *category, const char *method, int granted)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_ACCESSIBILITY_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"category\":\"");  jb_esc(j, category); jb_c(j, '"');
    jb_s(j, ",\"method\":");      jb_str_or_null(j, method);
    jb_s(j, ",\"code\":");        jb_u64(j, e->code);
    jb_s(j, ",\"granted\":");
    if (granted < 0)
        jb_s(j, "null");
    else
        jb_s(j, granted ? "true" : "false");
    jb_c(j, '}');
}

void mod_emit_fileless_detect(struct jbuf *j, const struct fileless_detect_event *e,
                              const char *kind, const char *content,
                              const char *saved, const char *sha256, long long size)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_FILELESS_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"kind\":\"");      jb_esc(j, kind); jb_c(j, '"');
    jb_s(j, ",\"start\":\"");     jb_hex(j, e->start); jb_c(j, '"');
    jb_s(j, ",\"size\":");        jb_u64(j, e->size);
    jb_s(j, ",\"anon_name\":\""); jb_esc(j, e->anon_name); jb_c(j, '"');
    jb_s(j, ",\"content\":");     jb_str_or_null(j, content);
    jb_s(j, ",\"saved\":");
    if (saved) {
        jb_s(j, "{\"file\":\"");   jb_esc(j, saved); jb_c(j, '"');
        jb_s(j, ",\"sha256\":");   jb_str_or_null(j, sha256);
        jb_s(j, ",\"size\":");     jb_u64(j, size > 0 ? (unsigned long long)size : 0);
        jb_c(j, '}');
    } else {
        jb_s(j, "null");
    }
    jb_c(j, '}');
}

void mod_emit_screencapture_detect(struct jbuf *j, const struct screencapture_detect_event *e,
                                   const char *stage, const char *iface, const char *method)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");       jb_s(j, trace_type_name(TRACE_SCREENCAPTURE_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");      jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"stage\":\"");     jb_esc(j, stage); jb_c(j, '"');
    jb_s(j, ",\"interface\":");   jb_str_or_null(j, iface);
    jb_s(j, ",\"method\":");      jb_str_or_null(j, method);
    jb_s(j, ",\"code\":");
    if (iface) jb_u64(j, e->code); else jb_s(j, "null");
    jb_c(j, '}');
}

void mod_emit_dexload_detect(struct jbuf *j, const struct dexload_detect_event *e,
                             const char *kind, const char *path, long long after_drop_ms,
                             const char *saved, const char *sha256, long long size)
{
    static const char *const stages[] = { "?", "drop", "load", "delete", "memload" };
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");     jb_s(j, trace_type_name(TRACE_DEXLOAD_DETECT)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");      jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"stage\":\"");    jb_s(j, stages[e->stage <= DEXLOAD_STAGE_MEMLOAD ? e->stage : 0]); jb_c(j, '"');
    jb_s(j, ",\"kind\":\"");     jb_esc(j, kind); jb_c(j, '"');
    jb_s(j, ",\"path\":");       jb_str_or_null(j, path);
    jb_s(j, ",\"ino\":");        jb_u64(j, e->ino);
    if (e->stage == DEXLOAD_STAGE_MEMLOAD) {
        jb_s(j, ",\"start\":\"");  jb_hex(j, e->addr); jb_c(j, '"');
        jb_s(j, ",\"region_size\":"); jb_u64(j, e->len);
    }
    jb_s(j, ",\"exec\":");
    jb_s(j, e->stage == DEXLOAD_STAGE_LOAD ? (e->exec ? "true" : "false") : "null");
    jb_s(j, ",\"after_drop_ms\":");
    if (after_drop_ms >= 0) jb_u64(j, (unsigned long long)after_drop_ms); else jb_s(j, "null");
    jb_s(j, ",\"saved\":");
    if (saved) {
        jb_s(j, "{\"file\":\"");   jb_esc(j, saved); jb_c(j, '"');
        jb_s(j, ",\"sha256\":");   jb_str_or_null(j, sha256);
        jb_s(j, ",\"size\":");     jb_u64(j, size > 0 ? (unsigned long long)size : 0);
        jb_c(j, '}');
    } else {
        jb_s(j, "null");
    }
    jb_c(j, '}');
}

void mod_emit_perm_change(struct jbuf *j, unsigned long long ts_ns, const char *pkg,
                          const char *key, const char *change,
                          const char *old_val, const char *new_val)
{
    const char *cat = pw_category(key);
    const char *colon = strchr(key, ':');
    const char *name = colon ? colon + 1 : key;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");    jb_s(j, trace_type_name(TRACE_PERM_CHANGE)); jb_c(j, '"');
    jb_s(j, ",\"ts_ns\":");     jb_u64(j, ts_ns);
    jb_s(j, ",\"package\":");   jb_str_or_null(j, pkg);
    jb_s(j, ",\"category\":\""); jb_esc(j, cat);    jb_c(j, '"');
    jb_s(j, ",\"name\":\"");   jb_esc(j, name);     jb_c(j, '"');
    jb_s(j, ",\"change\":\""); jb_esc(j, change);   jb_c(j, '"');
    jb_s(j, ",\"old\":");       jb_str_or_null(j, old_val);
    jb_s(j, ",\"new\":");       jb_str_or_null(j, new_val);
    jb_c(j, '}');
}

void mod_emit_binder_api(struct jbuf *j, const struct binder_api_event *e,
                         const char *iface, const char *method,
                         const struct binder_cp_detail *cp)
{
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");      jb_s(j, trace_type_name(TRACE_BINDER_API)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");         jb_u64(j, e->h.pid);
    jb_s(j, ",\"tid\":");         jb_u64(j, e->h.tid);
    jb_s(j, ",\"ts_ns\":");       jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"interface\":");   jb_str_or_null(j, iface);
    jb_s(j, ",\"method\":");      jb_str_or_null(j, method);
    jb_s(j, ",\"code\":");        jb_u64(j, e->code);
    jb_s(j, ",\"oneway\":");      jb_s(j, (e->flags & 0x01) ? "true" : "false");
    if (cp && cp->uri[0]) {
        jb_s(j, ",\"uri\":\""); jb_esc(j, cp->uri); jb_c(j, '"');
    } else if (cp && cp->authority[0]) {
        jb_s(j, ",\"call\":{\"authority\":\""); jb_esc(j, cp->authority);
        jb_s(j, "\",\"method\":\"");              jb_esc(j, cp->method);
        jb_s(j, "\",\"arg\":");                    jb_str_or_null(j, cp->arg[0] ? cp->arg : NULL);
        jb_c(j, '}');
    }
    jb_c(j, '}');
}

void mod_emit_net(struct jbuf *j, const struct net_event *e, const char *dest,
                  const char *host, const char *host_source)
{
    static const char *const kinds[] = { "?", "open", "close", "dns" };
    const char *proto = e->proto == NET_PROTO_TCP ? "tcp" : e->proto == NET_PROTO_UDP ? "udp" : NULL;
    jb_c(j, '{');
    jb_s(j, "\"type\":\"");     jb_s(j, trace_type_name(TRACE_NET)); jb_c(j, '"');
    jb_s(j, ",\"pid\":");        jb_u64(j, e->h.pid);
    jb_s(j, ",\"ts_ns\":");      jb_u64(j, e->ts_ns);
    jb_s(j, ",\"comm\":\"");     jb_esc(j, e->comm); jb_c(j, '"');
    jb_s(j, ",\"event\":\"");    jb_s(j, kinds[e->kind <= NET_EV_DNS ? e->kind : 0]); jb_c(j, '"');
    jb_s(j, ",\"proto\":");      jb_str_or_null(j, proto);
    jb_s(j, ",\"dest\":");       jb_str_or_null(j, dest);
    jb_s(j, ",\"host\":");       jb_str_or_null(j, host);
    jb_s(j, ",\"host_source\":"); jb_str_or_null(j, host_source);
    if (e->kind == NET_EV_CLOSE) {
        jb_s(j, ",\"tx\":");          jb_u64(j, e->tx);
        jb_s(j, ",\"rx\":");          jb_u64(j, e->rx);
        jb_s(j, ",\"duration_ms\":"); jb_u64(j, e->ts_ns > e->first_ts_ns
                                              ? (e->ts_ns - e->first_ts_ns) / 1000000ULL : 0);
    } else {
        jb_s(j, ",\"tx\":null,\"rx\":null,\"duration_ms\":null");
    }
    jb_c(j, '}');
}
