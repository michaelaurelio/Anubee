// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>      
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "funcs.h"
#include "funcs.skel.h"
#include "funcs-priv.h"
#include "common/lib_trace.h"
#include "common/launch.h"
#include "common/probe_resolve.h"
#include "common/probe_spec_loader.h"
#include "common/target_validate.h"
#include "common/pattern_match.h"
#include "common/decode.h"
#include "common/emit.h"
#include "common/runtime.h"
#include "common/evqueue.h"
#include "common/engine_args.h"
#include "common/maps.h"
#include "common/stack_snapshot.h"
#include "common/managed_frame.h"
#include "common/coverage.h"
#include "common/art_buildid.h"

// Argument parser module using argp.h
const char *argp_program_bug_address = "<vincent.kwee@binus.ac.id>";
static const char doc[] = "ares funcs — uprobe function tracer for Android apps (LOUD: writes BRK into target)"
    "\v"
    "Note: -o implies quiet; console output is suppressed when writing a file.";
static const char args_doc[] = "";

static const struct argp_option options[] = {
    { "package",        'P', "PACKAGE",      0, "Package to spawn",                                                                   0 },
    { "activity",       'A', "ACTIVITY",    0, "Override launch activity component (default: auto-resolve)",                          0 },
    { "resolve-syms",   'S', NULL,           0, "Symbol resolution mode: resolve and print symbols, no uprobe attachment",           0 },
    { "entry",          'e', "SPEC",         0, "Custom probe: MODULE!FUNC[@OFFSET][(S|V,...)] or MODULE@OFFSET[(S|V,...)]; MODULE/FUNC accept /regex/ for bulk matching", 0 },
    { "spec-file",      'F', "FILE",         0, "Load custom probe specs from file (one spec per line, # for comments)",            0 },
    { "caller-only",    'c', NULL,           0, "Print only the direct caller, suppress the rest of the call stack",                0 },
    { "snapshot",       1,   NULL,           0, "Capture stack snapshots for off-device DWARF unwinding (requires -o)",             0 },
    { "no-snapshot",    2,   NULL,           0, "Disable stack snapshots (default)",                                                 0 },
    COMMON_ARGP_OPTIONS,
    TARGET_ARGP_OPTIONS,
    { 0 }
};

struct args {
    struct common_args c;          // -o -v -q -J -b -Q (shared with syscalls)
    struct target_args tgt;
    char package_name[256];
    char activity[256];
    bool resolve_syms;
    char custom_specs[64][512];
    int custom_spec_count;
    char spec_files[8][256];
    int spec_file_count;
    bool caller_only;
    int  want_snap;       /* --snapshot */
};

static void copy_str(char *dst, const char *src, size_t dstsz)
{
    if (dstsz == 0)
        return;
    size_t n = strnlen(src, dstsz - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static error_t parse_opts(int key, char *arg, struct argp_state *state)
{
    struct args *args = state->input;
    switch(key) {
        case 'P':
            copy_str(args->package_name, arg, sizeof(args->package_name));
            break;

        case 'A':
            copy_str(args->activity, arg, sizeof(args->activity));
            break;

        case 'v':
        case 'o':
        case 'q':
        case 'Q':
        case 'J':
        case 'b':
            return parse_common_arg(key, arg, state, &args->c);

        case 'S':
            args->resolve_syms = true;
            break;

        case 'e':
            if (args->custom_spec_count < 64)
                copy_str(args->custom_specs[args->custom_spec_count++], arg, 512);
            else
                fprintf(stderr, "funcs: warning — spec cap (64) reached; '%s' ignored\n", arg);
            break;

        case 'F':
            if (args->spec_file_count < 8)
                copy_str(args->spec_files[args->spec_file_count++], arg, 256);
            else
                fprintf(stderr, "funcs: warning — spec-file cap (8) reached; '%s' ignored\n", arg);
            break;

        case 'c':
            args->caller_only = true;
            break;

        case 1:
            args->want_snap = 1;
            break;

        case 2:
            args->want_snap = 0;
            break;

        // No arguments case
        case ARGP_KEY_END:
            validate_pid_or_package(state, args->tgt.n,
                args->package_name[0] ? args->package_name : NULL);
            validate_have_selector(state,
                args->custom_spec_count + args->spec_file_count,
                "-e SPEC or -F FILE");
            break;
        
        case 'p':
        case ARES_KEY_SIBLINGS:
        case ARES_KEY_NO_FOLLOW:
            return parse_target_arg(key, arg, state, &args->tgt);

        // Default case
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = { options, parse_opts, args_doc, doc, 0, 0, 0 };

static int ends_with(const char *s, const char *suf)
{
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && !strcmp(s + ls - lf, suf);
}


// Application UID resolver 
// launch/UID helpers (sh_exec / resolve_uid / get_pid_uid / resolve_component)
// moved to src/common/launch.{c,h} as ares_*; shared with the correlate engine.


// Ctrl-C / SIGTERM → ares_install_stop_handler (cmd_funcs only, not under trace).
// sig_atomic_t so the same type can be shared with the kprobe engine under trace.
static volatile sig_atomic_t exiting = 0;

// Engine state shared across funcs_setup / funcs_run / funcs_teardown.
static struct ring_buffer *g_events_rb;
struct funcs_bpf *skel = NULL;  // must precede funcs_drops_tick below
// Resolution context: file-static so handle_event can safely dereference it
// after funcs_setup returns (all fields point at file-scope globals).
static struct probe_resolve_ctx g_rctx;
static char g_funcs_pkg[256];           // package to launch (spawn mode), else ""
static char g_funcs_activity[256];      // launch activity override (empty = auto-resolve)
static int  g_funcs_uid;               // resolved UID for the launch banner

// Output sink: shared ares_sink for structured JSONL; stdout/stderr for human text.
static struct ares_sink g_sink;

// Coverage-health record (CR5). Mutated only from process_call_return()'s STACK
// branch, which (N1 fix) runs exclusively on the worker thread; read at teardown
// only after pthread_join(g_worker, ...) has returned, so the worker is no longer
// running - no lock needed (same reasoning as syscalls.c's g_cov).
static struct ares_coverage g_cov = { .engine = "funcs" };

// Stack-snapshot sidecar (JSON Lines), written by the drain thread only (no lock).
static FILE               *g_stacks;
static unsigned long long  g_stack_count;

// Worker-thread drain: ring callback pushes CALL/RETURN; worker pops + processes.
static struct ares_evq g_q;
static pthread_t       g_worker;
static int             g_worker_started;

static bool g_quiet = false;

// Drop ticker state — reset at funcs_run entry; matches syscalls_drops_tick pattern.
static int g_funcs_drop_ticks;
static unsigned long long g_funcs_last_drops;
static void funcs_drops_tick(void *ctx)
{
    (void)ctx;
    if (++g_funcs_drop_ticks < 5)            // ~1s at 200ms/tick (matches syscalls)
        return;
    g_funcs_drop_ticks = 0;
    pthread_mutex_lock(&g_q.m);
    unsigned long long qd = g_q.dropped;     // worker thread writes this concurrently
    pthread_mutex_unlock(&g_q.m);
    unsigned long long d = ares_drops_read(bpf_map__fd(skel->maps.dropped)) + qd;
    if (d > g_funcs_last_drops) {
        fprintf(stderr, "[drops] %llu event(s) dropped so far\n", d);
        g_funcs_last_drops = d;
    }
}

// ponytail: three independent mutexes, never nested (disjoint critical sections).
// g_sink_lock serializes g_sink writes across the drain thread (lib/unlib records)
// and the worker thread (call/return records); see emit.h for the single-writer contract.
static pthread_mutex_t g_targets_lock = PTHREAD_MUTEX_INITIALIZER; // probe_targets[] + count
static pthread_mutex_t g_out_lock     = PTHREAD_MUTEX_INITIALIZER; // stdout/stderr line serializer
static pthread_mutex_t g_sink_lock    = PTHREAD_MUTEX_INITIALIZER; // g_sink (multi-writer: drain lib/unlib + worker call/return)

void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void out_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_out_lock);
    vprintf(fmt, ap);
    pthread_mutex_unlock(&g_out_lock);
    va_end(ap);
}

void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&g_out_lock);
    vfprintf(stderr, fmt, ap);
    pthread_mutex_unlock(&g_out_lock);
    va_end(ap);
}

// Top-level event line, prepends "HH:MM:SS " to stdout.
void ts_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)
{
    time_t t; time(&t);
    char ts_buf[16];
    strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", localtime(&t));
    pthread_mutex_lock(&g_out_lock);
    printf("%s ", ts_buf);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&g_out_lock);
}


probe_target_t probe_targets[4096];
int probe_target_count = 0;

static probe_target_t retired_targets[4096];
static int retired_count;

// addr -> probe_target_t* cache (AA4). probe_targets[]+retired_targets[] cap at
// 4096 each (8192 total distinct addresses, worst case), so a fixed 16384-slot
// table stays <=50% loaded even at that ceiling — no grow/rehash needed, unlike
// symbolize.c's sc_ent (which caches an unbounded (pid,addr) set over a trace).
// Guarded by g_targets_lock, same as the arrays it indexes.
#define PT_HASH_CAP (1u << 14)   /* 16384, power of 2 */
struct pt_hash_ent { __u64 addr; probe_target_t *target; int used; };
static struct pt_hash_ent pt_hash[PT_HASH_CAP];

static uint64_t pt_hash_fn(__u64 addr)
{
    uint64_t h = addr;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

// Both must be called with g_targets_lock held.
static probe_target_t *pt_hash_get(__u64 addr)
{
    size_t mask = PT_HASH_CAP - 1, i = pt_hash_fn(addr) & mask;
    for (size_t probe = 0; probe < PT_HASH_CAP; probe++) {
        struct pt_hash_ent *e = &pt_hash[i];
        if (!e->used) return NULL;
        if (e->addr == addr) return e->target;
        i = (i + 1) & mask;
    }
    return NULL;
}

static void pt_hash_put(__u64 addr, probe_target_t *target)
{
    size_t mask = PT_HASH_CAP - 1, i = pt_hash_fn(addr) & mask;
    while (pt_hash[i].used && pt_hash[i].addr != addr)
        i = (i + 1) & mask;
    pt_hash[i].used = 1;
    pt_hash[i].addr = addr;
    pt_hash[i].target = target;
}

bool verbose = false;
bool resolve_syms = false;
bool caller_only = false;

custom_probe_spec_t custom_probe_specs[64];
int custom_probe_spec_count = 0;


struct bpf_link *probe_links[4096];
struct bpf_link *probe_ret_links[4096];
static struct bpf_link *g_follow_fork_link = NULL;

static probe_target_t *find_target_by_entry_addr(__u64 entry_addr, pid_t pid, bool *used_fallback)
{
    *used_fallback = false;
    probe_target_t *result = NULL;

    // ponytail: coarse mutex, held across the /proc miss path; per-entry locking only if contention shows.
    pthread_mutex_lock(&g_targets_lock);

    result = pt_hash_get(entry_addr);

    if (!result) {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *f = fopen(maps_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f) && !result) {
                struct ares_map_line ml;
                if (!ares_parse_maps_line(line, &ml)) continue;
                if (entry_addr < ml.start || entry_addr >= ml.end) continue;
                if (!ml.exec || ml.path[0] != '/') continue;

                unsigned long file_offset = (unsigned long)(entry_addr - ml.start)
                                          + (unsigned long)ml.off;

                for (int i = 0; i < probe_target_count; i++) {
                    if (probe_targets[i].offset == file_offset &&
                        strcmp(probe_targets[i].mod_path, ml.path) == 0) {
                        probe_targets[i].runtime_entry_addr = entry_addr;
                        result = &probe_targets[i];
                        pt_hash_put(entry_addr, &probe_targets[i]);
                        break;
                    }
                }
            }
            fclose(f);
        }
    }

    // Fallback: use the lower-12-bit invariant. ASLR keeps the base page-aligned
    // (multiple of 0x1000), so (base + file_offset) & 0xFFF == file_offset & 0xFFF
    // always holds. Search both active and retired targets (retired = removed by UNMAP
    // but may still have in-flight events). Two entries with the same lower 12 bits
    // but different offset+mod_path = ambiguous, skip.
    if (!result) {
        unsigned long low12 = (unsigned long)(entry_addr & 0xFFF);
        probe_target_t *candidate = NULL;
        bool ambiguous = false;
        for (int pass = 0; pass < 2 && !ambiguous; pass++) {
            probe_target_t *arr = (pass == 0) ? probe_targets : retired_targets;
            int cnt = (pass == 0) ? probe_target_count : retired_count;
            for (int i = 0; i < cnt && !ambiguous; i++) {
                if ((arr[i].offset & 0xFFF) != low12) continue;
                if (!candidate) {
                    candidate = &arr[i];
                } else if (arr[i].offset != candidate->offset ||
                           strcmp(arr[i].mod_path, candidate->mod_path) != 0) {
                    ambiguous = true;
                }
            }
        }
        if (candidate && !ambiguous) {
            candidate->runtime_entry_addr = entry_addr;
            *used_fallback = true;
            result = candidate;
            pt_hash_put(entry_addr, candidate);
        }
    }

    pthread_mutex_unlock(&g_targets_lock);
    return result;
}


static pid_t find_zygote_pid(void)
{
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *ent;
    pid_t result = -1;
    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        char path[64], cmdline[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (n <= 0) continue;
        cmdline[n] = '\0';
        if (strcmp(cmdline, "zygote64") == 0 || strcmp(cmdline, "zygote") == 0) {
            result = pid;
            break;
        }
    }
    closedir(dir);
    return result;
}

// Store + attach one resolved custom-spec target. Shared by both the
// exact-match spec path and the bulk /regex/ func-match path (EPIC H12).
static void attach_one_custom_target(const struct probe_resolve_ctx *ctx, const char *path,
                                      pid_t uprobe_pid, unsigned long map_start,
                                      unsigned long map_end, probe_target_t tgt)
{
    pid_t pid = tgt.pid;
    if (is_duplicate(ctx->targets, *ctx->target_count, path, tgt.offset))
        return;

    int idx = *ctx->target_count;
    ctx->targets[idx] = tgt;
    probe_links[idx] = NULL;
    (*ctx->target_count)++;

    const char *bname = strrchr(path, '/');
    bname = bname ? bname + 1 : path;
    const char *label = tgt.func_name[0] ? tgt.func_name : "?";

    if (resolve_syms) {
        ts_print("[sym] > %s!%s @ 0x%lx\n", bname, label, tgt.offset);
    } else {
        ts_print("[spec] > %s!%s @ 0x%lx%s\n", bname, label, tgt.offset,
                  tgt.ret_only ? " (ret-only)" :
                  tgt.ret_type != ARG_NONE ? " [+ret]" : "");
        struct bpf_program *entry_prog = tgt.ret_only
            ? skel->progs.uprobe_save_only
            : skel->progs.uprobe_open;
        probe_links[idx] = bpf_program__attach_uprobe(
            entry_prog, false, uprobe_pid, path, tgt.offset);
        if (!probe_links[idx] && map_start && map_end) {
            char map_files[80];
            ares_map_files_path(map_files, sizeof(map_files), pid, map_start, map_end);
            if (access(map_files, F_OK) == 0) {
                probe_links[idx] = bpf_program__attach_uprobe(
                    entry_prog, false, uprobe_pid, map_files, tgt.offset);
                if (probe_links[idx])
                    ts_print("[spec] > attached via map_files (file deleted): %s!%s\n",
                              bname, label);
                else
                    err_print(" [spec] > FAILED: %s!%s\n", bname, label);
            } else {
                ts_print("[spec] > MISSED: %s!%s (mapping gone before attach)\n",
                          bname, label);
            }
        } else if (!probe_links[idx]) {
            err_print(" [spec] > FAILED: %s!%s\n", bname, label);
        }

        if (tgt.ret_type != ARG_NONE || tgt.ret_only) {
            probe_ret_links[idx] = bpf_program__attach_uprobe(
                skel->progs.uretprobe_open, true, uprobe_pid, path, tgt.offset);
            if (!probe_ret_links[idx])
                err_print(" [spec] > FAILED ret: %s!%s\n", bname, label);
        }
    }
}

static void apply_custom_specs_for_file(const struct probe_resolve_ctx *ctx,
                                         pid_t pid, const char *path, pid_t uprobe_pid,
                                         unsigned long map_start, unsigned long map_end)
{
    int max = ctx->targets_cap;
    for (int s = 0; s < ctx->custom_spec_count && *ctx->target_count < max; s++) {
        const custom_probe_spec_t *spec = &ctx->custom_specs[s];
        // Multi-kind files (EPIC H11) may carry syscall:/lib:/mod: lines meant
        // for other engines -- only funcs-kind specs describe a uprobe target.
        if (spec->kind != SPEC_KIND_FUNCS) continue;
        if (!custom_spec_matches_path(spec, path)) continue;

        if (pm_is_regex(spec->func)) {
            // Bulk match: one spec, potentially many symbols (EPIC H12,
            // replaces -i's "scan every symbol in a matched module" shape).
            probe_target_t matches[256];
            int cap = max - *ctx->target_count;
            if (cap > 256) cap = 256;
            if (cap <= 0) continue;
            int n = resolve_custom_spec_matches_for_path(pid, path, spec, matches, cap);
            if (n == cap)
                err_print("   [err] > custom spec: regex match cap (%d) reached for %s!%s in %s; "
                          "additional matches may exist and were ignored\n",
                          cap, spec->mod, spec->func, path);
            for (int m = 0; m < n && *ctx->target_count < max; m++)
                attach_one_custom_target(ctx, path, uprobe_pid, map_start, map_end, matches[m]);
            continue;
        }

        probe_target_t tgt;
        if (resolve_custom_spec_for_path(pid, path, spec, &tgt) != 0) {
            if (ctx->verbose) err_print("   [err] > custom spec: could not resolve %s!%s in %s\n",
                spec->mod, spec->func[0] ? spec->func : "?", path);
            continue;
        }
        attach_one_custom_target(ctx, path, uprobe_pid, map_start, map_end, tgt);
    }
}

// Worker thread: pop CALL/RETURN records and process them off the poll thread.
static void process_call_return(const void *data, size_t data_sz)
{
    const struct trace_event_header *header = data;
    if (data_sz < sizeof(*header)) return;

    if (header->type == ARES_EVENT_CALL) {
        if (data_sz < sizeof(struct event)) return;
        const struct event *e = data;

        bool used_fallback = false;
        probe_target_t *target = find_target_by_entry_addr(e->entry_addr, header->pid, &used_fallback);
        if (target) {
            const char *bname = strrchr(target->mod_path, '/');
            bname = bname ? bname + 1 : target->mod_path;
            if (!g_quiet)
                ts_print("[event] > [CALL] PID:%d PPID:%d %s!%s @ 0x%lx%s\n",
                    e->h.pid, e->ppid, bname, target->func_name, target->offset,
                    used_fallback ? " (resolved from known offset)" : "");
            if (g_sink.f) {
                // Resolve backtrace symbols the same way the console does (below) so
                // the file record carries them too (parity with syscalls). Done
                // before taking g_sink_lock — sym_resolve only reads e, not the sink.
                char symbuf[STACK_DEPTH][320];
                const char *syms[STACK_DEPTH];
                for (int i = 0; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
                    if (!e->call_stack[i]) { syms[i] = NULL; continue; }
                    sym_resolve((int)e->h.pid, e->call_stack[i], symbuf[i], sizeof(symbuf[i]));
                    syms[i] = symbuf[i];
                }
                pthread_mutex_lock(&g_sink_lock);
                g_sink.jb.len = 0;
                char js[208];
                const char *jsp = ares_jcache_get(e->stack_id, js, sizeof(js)) ? js : NULL;
                funcs_emit_call(&g_sink.jb, e, bname, target->func_name, target, jsp, syms);
                ares_sink_emit(&g_sink);
                pthread_mutex_unlock(&g_sink_lock);
            }
        } else {
            if (!g_quiet)
                ts_print("[event] > [CALL] PID:%d PPID:%d %s!??? @ 0x%llx (unresolved)\n",
                    e->h.pid, e->ppid, e->comm, (unsigned long long)e->entry_addr);
            return;
        }

        if (!g_quiet && target->arg_count >= 0) {
            for (int i = 0; i < target->arg_count; i++) {
                if (target->arg_types[i] == ARG_STR) {
                    if (e->is_str[i])
                        out_print("         [event]   | args[%d] \"%s\"\n", i, e->strings[i]);
                    else
                        out_print("         [event]   | args[%d] 0x%lx (?str)\n", i, (unsigned long)e->args[i]);
                } else if (target->arg_types[i] == ARG_FD) {
                    long fd_val = (long)e->args[i];
                    if (fd_val == -100L) {
                        char cwd[256], cwd_link[32];
                        snprintf(cwd_link, sizeof(cwd_link), "/proc/%d/cwd", (int)e->h.pid);
                        ssize_t rn = readlink(cwd_link, cwd, sizeof(cwd) - 1);
                        if (rn > 0) { cwd[rn] = '\0'; out_print("         [event]   | args[%d] AT_FDCWD (%s)\n", i, cwd); }
                        else         out_print("         [event]   | args[%d] AT_FDCWD\n", i);
                    } else {
                        char fpath[256], fd_link[64];
                        snprintf(fd_link, sizeof(fd_link), "/proc/%d/fd/%ld", (int)e->h.pid, fd_val);
                        ssize_t rn = readlink(fd_link, fpath, sizeof(fpath) - 1);
                        if (rn > 0) { fpath[rn] = '\0'; out_print("         [event]   | args[%d] %ld -> \"%s\"\n", i, fd_val, fpath); }
                        else         out_print("         [event]   | args[%d] 0x%lx\n", i, (unsigned long)fd_val);
                    }
                } else if (target->arg_types[i] == ARG_SOCKADDR) {
                    char sbuf[128];
                    if (decode_sockaddr(e->sock[i], SOCK_ADDR_MAX, sbuf, sizeof(sbuf)))
                        out_print("         [event]   | args[%d] %s\n", i, sbuf);
                    else
                        out_print("         [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
                } else {
                    out_print("         [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
                }
            }
            for (int i = 0; i + 1 < target->arg_count; i++) {
                if (target->arg_types[i] == ARG_FD &&
                    target->arg_types[i + 1] == ARG_STR &&
                    e->is_str[i + 1] &&
                    e->strings[i + 1][0] != '\0' && e->strings[i + 1][0] != '/') {
                    long fd_val = (long)e->args[i];
                    char dir[256], link_path[64];
                    if (fd_val == -100L)
                        snprintf(link_path, sizeof(link_path), "/proc/%d/cwd", (int)e->h.pid);
                    else
                        snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%ld", (int)e->h.pid, fd_val);
                    ssize_t rn = readlink(link_path, dir, sizeof(dir) - 1);
                    if (rn > 0) {
                        dir[rn] = '\0';
                        out_print("         [event]   | full path: \"%s/%s\"\n", dir, e->strings[i + 1]);
                    }
                }
            }
        } else if (!g_quiet) {
            for (int i = 0; i < NUM_ARGS; i++) {
                if (e->is_str[i])
                    out_print("         [event]   | args[%d] \"%s\"\n", i, e->strings[i]);
                else
                    out_print("         [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
            }
        }

        if (!g_quiet && e->caller_addr) {
            char caller_sym[320];
            sym_resolve(header->pid, e->caller_addr, caller_sym, sizeof(caller_sym));
            out_print("         [event]   | caller: %s\n", caller_sym);
        }

        if (!g_quiet && !caller_only) {
            for (__u32 i = 2; i < e->stack_depth; i++) {
                if (!e->call_stack[i]) break;
                char frame_sym[320];
                sym_resolve(header->pid, e->call_stack[i], frame_sym, sizeof(frame_sym));
                out_print("         [event]   | #%u %s\n", i, frame_sym);
            }
        }
        return;
    }

    if (header->type == ARES_EVENT_RETURN) {
        if (data_sz < sizeof(struct event)) return;
        const struct event *e = data;

        bool used_fallback = false;
        probe_target_t *target = find_target_by_entry_addr(e->entry_addr, header->pid, &used_fallback);

        const char *bname = "???";
        const char *fname = "???";
        unsigned long offset = 0;
        uint8_t ret_type = ARG_VAL;
        int arg_count = -1;
        uint8_t *arg_types = NULL;

        if (target) {
            const char *b = strrchr(target->mod_path, '/');
            bname    = b ? b + 1 : target->mod_path;
            fname    = target->func_name;
            offset   = target->offset;
            ret_type = (target->ret_type != ARG_NONE) ? target->ret_type : ARG_VAL;
            arg_count = target->arg_count;
            arg_types = target->arg_types;
        }

        char elapsed_buf[32] = "";
        if (e->elapsed_ns > 0) {
            if (e->elapsed_ns < 1000)
                snprintf(elapsed_buf, sizeof(elapsed_buf), " +%lluns",
                         (unsigned long long)e->elapsed_ns);
            else if (e->elapsed_ns < 1000000)
                snprintf(elapsed_buf, sizeof(elapsed_buf), " +%.1fus",
                         (double)e->elapsed_ns / 1000.0);
            else
                snprintf(elapsed_buf, sizeof(elapsed_buf), " +%.1fms",
                         (double)e->elapsed_ns / 1000000.0);
        }

        char retval_buf[MAX_STR_LEN + 4];
        if (ret_type == ARG_STR && e->is_str[0])
            snprintf(retval_buf, sizeof(retval_buf), "\"%s\"", e->strings[0]);
        else
            snprintf(retval_buf, sizeof(retval_buf), "0x%lx", (unsigned long)e->retval);

        if (!g_quiet)
            ts_print("[event] > [RET]  PID:%d %s!%s @ 0x%lx%s%s -> %s\n",
                header->pid, bname, fname, offset,
                used_fallback ? " (resolved from known offset)" : "",
                elapsed_buf, retval_buf);

        if (g_sink.f) {
            // Resolve before taking the lock — same reasoning as the CALL path above.
            char symbuf[STACK_DEPTH][320];
            const char *syms[STACK_DEPTH];
            for (int i = 0; i < (int)e->stack_depth && i < STACK_DEPTH; i++) {
                if (!e->call_stack[i]) { syms[i] = NULL; continue; }
                sym_resolve((int)e->h.pid, e->call_stack[i], symbuf[i], sizeof(symbuf[i]));
                syms[i] = symbuf[i];
            }
            pthread_mutex_lock(&g_sink_lock);
            g_sink.jb.len = 0;
            funcs_emit_return(&g_sink.jb, e, bname, fname, target, syms);
            ares_sink_emit(&g_sink);
            pthread_mutex_unlock(&g_sink_lock);
        }

        if (!g_quiet && arg_count >= 0) {
            for (int i = 0; i < arg_count && i < NUM_ARGS - 1; i++) {
                if (arg_types[i] == ARG_STR && e->is_str[i + 1])
                    out_print("         [event]   | args[%d] (out) \"%s\"\n", i, e->strings[i + 1]);
            }
        }

        if (g_quiet) return;
        __u32 stack_limit = caller_only ? 2 : e->stack_depth;
        for (__u32 i = 1; i < stack_limit; i++) {
            if (!e->call_stack[i]) break;
            char frame_sym[320];
            sym_resolve(header->pid, e->call_stack[i], frame_sym, sizeof(frame_sym));
            if (i == 1)
                out_print("         [event]   | caller: %s\n", frame_sym);
            else
                out_print("         [event]   | #%u %s\n", i, frame_sym);
        }
    }

    if (header->type == ARES_EVENT_STACK) {
        if (data_sz < (int)sizeof(struct ares_stack_snapshot)) return;
        // ponytail: worker-thread scratch jbuf — worker is single-writer, no lock
        // (N1 fix: this used to run on the drain thread, same single-writer
        // reasoning applied there; only the thread changed).
        static struct jbuf sj;
        sj.len = 0;
        ares_stack_snapshot_emit_json(&sj, data);
        if (sj.b && sj.len)
            fwrite(sj.b, 1, sj.len, g_stacks);
        g_stack_count++;

        const struct ares_stack_snapshot *s = (const void *)data;
        uint64_t pcs[64], sps[64];
        struct cfi_step_diag diags[64];
        // Unconditional zero-init: cfi_unwind_snapshot's early-exit break
        // paths (frame cap, maps miss) don't always write out_diags[n-1],
        // so an un-memset buffer would leave the terminal stop_reason as
        // uninitialized stack garbage aliasing a valid enum value and
        // silently corrupting g_cov.cfi_stop[]. Zero means an unwritten
        // terminal reads as CFI_OK (0).
        memset(diags, 0, sizeof(diags));
        int n = cfi_unwind_snapshot((int)s->h.pid, s, pcs, 64, sps, diags);
        if (n > 0) {
            g_cov.snaps_total++;
            g_cov.cfi_walks++;
            int stop_reason = diags[n - 1].stop_reason;
            if (stop_reason >= 0 && stop_reason < ARES_CFI_STOP_N)
                g_cov.cfi_stop[stop_reason]++;

            // AA9: resolve each frame once and share it with both emitters
            // below (they previously each re-resolved the same n symbols).
            char sym_store[64][320];
            const char *syms[64];
            int nsym = n < 64 ? n : 64;
            for (int i = 0; i < nsym; i++) {
                sym_resolve((int)s->h.pid, pcs[i], sym_store[i], sizeof(sym_store[i]));
                syms[i] = sym_store[i];
            }

            struct jbuf cj = {0};
            ares_emit_cfi_stack_json(&cj, (int)s->h.pid, s, pcs, sps, n, syms, NULL);
            if (cj.b && cj.len) fwrite(cj.b, 1, cj.len, g_stacks);
            free(cj.b);
            char frag[208];
            if (ares_managed_chain((int)s->h.pid, s, pcs, sps, n, syms, frag, sizeof(frag)) > 0)
                ares_jcache_put(s->stack_id, frag);
        }
    }
}

static void *funcs_worker_main(void *arg)
{
    (void)arg;
    static char rec[sizeof(struct ares_stack_snapshot) + 64];
    size_t sz;
    unsigned long flushed = 0;
    while (ares_evq_pop(&g_q, rec, sizeof(rec), &sz)) {
        process_call_return(rec, sz);
        if (g_sink.f && (++flushed & ARES_FLUSH_MASK) == 0)
            ares_sink_flush(&g_sink); // fflush only; glibc FILE ops are thread-safe; no g_sink_lock needed
    }
    return NULL;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct trace_event_header *header = data;
    if (data_sz < sizeof(*header)) return 0;
    struct probe_resolve_ctx *rctx = ctx;  // routed via ring_buffer__new (see cmd_funcs)

    // Structured record status (per event type):
    //   CALL   — done (worker via funcs_emit_call)
    //   RETURN — done (worker via funcs_emit_return)
    //   LIB    — done (drain via ares_libtrace_emit_lib, g_sink_lock)
    //   UNLIB  — done (drain via ares_libtrace_emit_unlib, g_sink_lock)
    //   STACK  — done (worker via process_call_return, N1 fix — mirrors syscalls'
    //            worker-only CFI/chain walk; queued here, not processed inline)

    if (header->type == ARES_EVENT_STACK) {
        if (g_stacks)
            ares_evq_push(&g_q, data, data_sz);
        return 0;
    }

    if (header->type == ARES_EVENT_MAP) {
        const struct lib_map_event *e = data;
        if (data_sz < sizeof(*e))
            return 0;

        if (verbose) err_print("         [event]   | MMAP : %s\n", e->name);
        char path[256];
        if (ares_libtrace_resolve_path(header->pid, e->start, e->name, path, sizeof(path)) != 0)
            return 0;

        // Emit structured lib record for every load (regardless of probe filter).
        // quiet=g_quiet||!verbose: sink always when -o; console [lib] line only under -v
        // (funcs already prints [uprobe]/[sym] attach lines — avoids double-reporting).
        if (g_sink.f || verbose) {
            pthread_mutex_lock(&g_sink_lock);
            ares_libtrace_emit_lib(&g_sink, g_quiet || !verbose, e, path, NULL);
            pthread_mutex_unlock(&g_sink_lock);
        }

        if (custom_probe_spec_count > 0)
            apply_custom_specs_for_file(rctx, header->pid, path, -1,
                                        (unsigned long)e->start, (unsigned long)e->end);

        return 0;
    }

    if (header->type == ARES_EVENT_UNMAP) {
        const struct lib_unmap_event *e = data;
        if (data_sz < sizeof(*e))
            return 0;

        if (g_sink.f || verbose) {
            pthread_mutex_lock(&g_sink_lock);
            ares_libtrace_emit_unlib(&g_sink, g_quiet || !verbose, e);
            pthread_mutex_unlock(&g_sink_lock);
        }

        return 0;
    }

    if (header->type == ARES_EVENT_CALL || header->type == ARES_EVENT_RETURN) {
        if (!resolve_syms)
            ares_evq_push(&g_q, data, data_sz);
        return 0;
    }

    return 0;
}


// La driver function
int funcs_setup(int argc, char **argv, const struct ares_run_ctx *rc)
{
    // Boilerplate setup
    int err = 0;
    int uid = -1;

    libbpf_set_print(ares_libbpf_quiet);

    // Argument parsing
    struct args args = { .c = COMMON_ARGS_INIT };
    // Pre-fill package from coordinator so ARGP_KEY_END validation passes
    // without requiring -P in the funcs argv section.
    if (rc && rc->pkg)
        copy_str(args.package_name, rc->pkg, sizeof(args.package_name));
    argp_parse(&argp, argc, argv, 0, NULL, &args);
    verbose = args.c.verbose;
    resolve_syms = args.resolve_syms;
    caller_only = args.caller_only;
    g_quiet = args.c.quiet || (args.c.output_file != NULL);

    if (args.c.output_file) {
        int jsonl = args.c.jsonl || ends_with(args.c.output_file, ".jsonl");
        if (ares_sink_open(&g_sink, args.c.output_file, "event", jsonl) != 0) {
            fprintf(stderr, "cannot open '%s': %s\n", args.c.output_file, strerror(errno));
            return 1;
        }
        // Stack-snapshot sidecar: opt-in (--snapshot), requires -o (snapshot is
        // meaningless without a structured output file to link it to).
        if (args.want_snap) {
            char sp[1040];
            snprintf(sp, sizeof(sp), "%s.stacks", args.c.output_file);
            g_stacks = fopen(sp, "w");
            if (!g_stacks)
                fprintf(stderr, "warning: cannot open snapshot sidecar '%s': %s\n",
                        sp, strerror(errno));
            else {
                setvbuf(g_stacks, malloc(8u << 20), _IOFBF, 8u << 20);
                printf("stack snapshots: %s\n", sp);
            }
        }
    }

    if (verbose) err_print("  [verb] > mode ON\n");
    if (resolve_syms) ts_print("[info] > symbol resolution mode\n");


    // Resolve application UID (if spawn mode)
    if (args.package_name[0] != '\0') {
        // Remember the package so the caller can launch it after setup returns.
        snprintf(g_funcs_pkg, sizeof(g_funcs_pkg), "%s", args.package_name);
        snprintf(g_funcs_activity, sizeof(g_funcs_activity), "%s", args.activity);
        uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(args.package_name);
        if (uid < 0) {
            err_print(" [spawn] > could not resolve UID for '%s' (installed? run as root?)\n", args.package_name);
            err = -1;
            goto cleanup;
        }
        g_funcs_uid = uid;
    }


    // Parse custom probe specs from -e flags
    for (int i = 0; i < args.custom_spec_count; i++) {
        if (parse_custom_probe_spec(args.custom_specs[i], &custom_probe_specs[custom_probe_spec_count], err_print) == 0)
            custom_probe_spec_count++;
    }

    // Parse custom probe specs from -F spec files
    for (int fi = 0; fi < args.spec_file_count; fi++) {
        if (load_probe_spec_file(args.spec_files[fi], custom_probe_specs, 64,
                                 &custom_probe_spec_count, err_print) != 0) {
            err = -1;
            goto cleanup;
        }
    }


    // Open, configure, load, attach BPF skeleton.
    // set_max_entries and set_autoattach must happen after open, before load.
    skel = funcs_bpf__open();
    if (!skel) {
        err_print("   [bpf] > failed to open skeleton\n");
        err = 1;
        goto cleanup;
    }

    bpf_program__set_autoattach(skel->progs.uprobe_open, false);
    bpf_program__set_autoattach(skel->progs.uprobe_save_only, false);
    bpf_program__set_autoattach(skel->progs.uretprobe_open, false);

    {
        int bufmb = args.c.bufmb;
        size_t bufbytes = ares_round_pow2((unsigned long)bufmb << 20);
        bpf_map__set_max_entries(skel->maps.events_rb, (unsigned int)bufbytes);
        skel->rodata->snapshot_enabled = (g_stacks != NULL) ? 1 : 0;

        // sockaddr_capture: on iff some custom probe spec (-c / spec file) tags an
        // arg as ARG_SOCKADDR. Only custom specs carry explicit arg types (the
        // mod/func regex auto-probe path uses the BPF heuristic, arg_count == -1),
        // and all specs are parsed by now (above), well before this rodata write —
        // which must land before funcs_bpf__load() freezes .rodata.
        int want_sock = 0;
        for (int i = 0; i < custom_probe_spec_count && !want_sock; i++)
            for (int a = 0; a < custom_probe_specs[i].arg_count; a++)
                if (custom_probe_specs[i].arg_types[a] == ARG_SOCKADDR) { want_sock = 1; break; }
        skel->rodata->sockaddr_capture = want_sock;
        if (funcs_bpf__load(skel)) {
            err_print("   [bpf] > failed to load skeleton\n");
            funcs_bpf__destroy(skel);
            skel = NULL;
            err = 1;
            goto cleanup;
        }
        ts_print("  [bpf] > ring buffer: %zu MB\n", bufbytes >> 20);
    }

    err = funcs_bpf__attach(skel);
    if (err) {
        err_print("   [bpf] > failed to attach (uprobe_mmap in kallsyms?)\n");
        goto cleanup;
    }

    elf_version(EV_CURRENT);

    // Resolution context: assigned into the file-static g_rctx (not a local) so
    // handle_event can safely dereference it after funcs_setup returns. All fields
    // point at file-scope globals that outlive the stack frame.
    g_rctx = (struct probe_resolve_ctx){
        .targets = probe_targets, .target_count = &probe_target_count,
        .targets_cap = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])),
        .custom_specs = custom_probe_specs, .custom_spec_count = custom_probe_spec_count,
        .verbose = verbose,
        .log = err_print,
    };

    g_events_rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, &g_rctx, NULL);
    if (!g_events_rb) {
        err = -1;
        err_print("    [rb] > failed to create ring buffer\n");
        goto cleanup;
    }


    // Find and resolve symbols in PID attach mode / spawn mode, then attach uprobes
    if (args.tgt.n > 0) {
        __u8 one = 1;
        for (int i = 0; i < args.tgt.n; i++) {
            __u32 tgid = (__u32)args.tgt.pids[i];
            bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tgid, &one, BPF_ANY);

            if (args.tgt.siblings) {
                int pid_uid = ares_get_pid_uid(args.tgt.pids[i]);
                if (pid_uid > 0) {
                    __u32 vuid = (__u32)pid_uid;
                    bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY);
                }
            }
        }

        if (!args.tgt.no_follow) {
            g_follow_fork_link = bpf_program__attach(skel->progs.ares_follow_fork);
            if (!g_follow_fork_link)
                fprintf(stderr, "funcs: follow-fork attach failed (non-fatal)\n");
        }

        // Apply custom probe specs for each PID
        if (custom_probe_spec_count > 0) {
            for (int p = 0; p < args.tgt.n; p++) {
                char maps_path[64];
                snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", args.tgt.pids[p]);
                FILE *mf = fopen(maps_path, "r");
                if (!mf) continue;
                char mline[512];
                while (fgets(mline, sizeof(mline), mf)) {
                    struct ares_map_line ml;
                    if (!ares_parse_maps_line(mline, &ml)) continue;
                    if (ml.path[0] != '/' || !ml.exec) continue;
                    apply_custom_specs_for_file(&g_rctx, args.tgt.pids[p], ml.path, args.tgt.pids[p], 0, 0);
                }
                fclose(mf);
            }
        }
    } else {
        // V4: scan Zygote's pre-loaded libs without ptrace; child inherits
        // BRK patches via CoW page table copy on fork
        pid_t zygote_pid = find_zygote_pid();
        if (zygote_pid < 0) {
            err_print("[zygote] > failed to find Zygote PID\n");
            err = -1;
            goto cleanup;
        }
        ts_print("[zygote] > scanning pre-loaded libs from PID %d\n", zygote_pid);

        if (custom_probe_spec_count > 0) {
            char cmaps[64];
            snprintf(cmaps, sizeof(cmaps), "/proc/%d/maps", zygote_pid);
            FILE *cf = fopen(cmaps, "r");
            if (cf) {
                char cline[512];
                while (fgets(cline, sizeof(cline), cf)) {
                    struct ares_map_line ml;
                    if (!ares_parse_maps_line(cline, &ml)) continue;
                    if (ml.path[0] != '/' || !ml.exec) continue;
                    apply_custom_specs_for_file(&g_rctx, zygote_pid, ml.path, -1, 0, 0);
                }
                fclose(cf);
            }
        }

        // Arm the UID filter BEFORE launching (target_uids gates the uprobes)
        // so the fresh process is caught from its first instruction.
        __u8 one = 1;
        __u32 vuid = (__u32)uid;
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
            err_print(" [spawn] > failed to set target UID: %s\n", strerror(errno));
            goto cleanup;
        }

        // The actual launch happens after setup returns (cmd_funcs standalone,
        // or the trace coordinator) so a single launch serves all armed engines.
    }

    // Start the worker drain thread last — probe_targets[] is now fully populated,
    // so the worker can look up targets without racing the setup-time resolve loops.
    if (ares_evq_init(&g_q, (size_t)args.c.queue_mb << 20) != 0) {
        err_print(" [work] > cannot allocate %d MB worker queue\n", args.c.queue_mb);
        err = -1;
        goto cleanup;
    }
    if (pthread_create(&g_worker, NULL, funcs_worker_main, NULL) != 0) {
        err_print(" [work] > cannot start worker thread\n");
        ares_evq_destroy(&g_q);
        err = -1;
        goto cleanup;
    }
    g_worker_started = 1;

    // Setup complete. The caller owns the single app launch (after this returns).
    return 0;

    // Setup failure lands here: clean up the partial state and report. teardown
    // is safe on partially-initialized state (everything it touches is global /
    // NULL-checked), so reuse it.
    cleanup:
        funcs_teardown();
        return err < 0 ? -err : 1;
}

int funcs_run(volatile sig_atomic_t *stop)
{
    g_funcs_drop_ticks = 0;
    g_funcs_last_drops = 0;
    int err = ares_rb_poll_until_cb(g_events_rb, stop, funcs_drops_tick, NULL);
    if (err < 0)
        err_print("   [err] > ring buffer poll error: %d\n", err);

    return err < 0 ? -err : 0;
}

void funcs_teardown(void)
{
    // Join the worker first: it reads probe_targets[] and writes g_sink.
    // Freeing links or closing the sink before the join would be a use-after-free.
    if (g_worker_started) {
        pthread_mutex_lock(&g_q.m);
        g_q.done = 1;
        pthread_cond_signal(&g_q.cv);
        pthread_mutex_unlock(&g_q.m);
        pthread_join(g_worker, NULL);
        g_worker_started = 0;
    }

    if (g_events_rb) {
        ring_buffer__free(g_events_rb);
        g_events_rb = NULL;
    }

    for (int i = 0; i < probe_target_count; i++) {
        if (probe_links[i])     bpf_link__destroy(probe_links[i]);
        if (probe_ret_links[i]) bpf_link__destroy(probe_ret_links[i]);
    }
    if (g_follow_fork_link) { bpf_link__destroy(g_follow_fork_link); g_follow_fork_link = NULL; }

    if (skel) {
        // Always report the final tally, so "no message" never means "didn't
        // check". Subsumes the old ares_drops_report: ring/queue drops are
        // coverage fields here. Safe to read g_cov here: the drain loop
        // (funcs_run's ring-buffer poll, the only writer) has already
        // returned and the worker thread has been joined above.
        int covfd = bpf_map__fd(skel->maps.coverage_stats);
        g_cov.snaps_truncated = ares_coverage_read(covfd, COV_TRUNC);
        g_cov.depth_capped    = ares_coverage_read(covfd, COV_DEPTH_CAP);
        g_cov.ring_drops      = ares_drops_read(bpf_map__fd(skel->maps.dropped));
        g_cov.queue_drops     = g_q.dropped;
        g_cov.managed_naming_off = ares_art_naming_disabled();
        ares_coverage_report(&g_sink, &g_cov);
        funcs_bpf__destroy(skel);
        skel = NULL;
    }
    ares_evq_destroy(&g_q);
    ares_sink_close(&g_sink);
    ares_sink_report(&g_sink);
    if (g_stacks) {
        fclose(g_stacks);
        g_stacks = NULL;
        fprintf(stderr, "wrote %llu stack snapshot%s to sidecar\n",
                g_stack_count, g_stack_count == 1 ? "" : "s");
        g_stack_count = 0;
    }
}

int cmd_funcs(int argc, char **argv)
{
    ares_install_stop_handler(&exiting);

    int ret = funcs_setup(argc, argv, NULL);
    if (ret != 0)
        return ret;             // setup already cleaned up on failure

    // Standalone: launch the package now that probes + UID are armed (spawn mode
    // only; -p PID attach mode has no package and never launches).
    if (g_funcs_pkg[0]) {
        ares_launch_banner(g_funcs_pkg, g_funcs_uid);
        if (ares_launch_app(g_funcs_pkg, g_funcs_activity[0] ? g_funcs_activity : NULL, NULL) != 0) {
            err_print(" [spawn] > failed to launch %s\n", g_funcs_pkg);
            funcs_teardown();
            return 1;
        }
    }

    funcs_run(&exiting);
    funcs_teardown();
    return 0;
}