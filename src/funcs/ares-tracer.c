// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <regex.h>
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

#include "ares-tracer.h"
#include "ares-tracer.skel.h"
#include "ares-tracer-priv.h"
#include "modules/module.h"
#include "common/lib_trace.h"
#include "common/launch.h"
#include "common/probe_resolve.h"
#include "common/emit.h"
#include "common/runtime.h"

static const ares_module_t *const all_modules[] = {
    &module_proc_event,
    &module_execve,
    &module_prop_read,
    NULL,
};
static const ares_module_t *active_modules[sizeof(all_modules)/sizeof(all_modules[0])];
static int active_module_count = 0;

// Argument parser module using argp.h
const char *argp_program_version = "ares-tracer 1.0";
const char *argp_program_bug_address = "<vincentferdinand.k@gmail.com>";
static const char doc[] = "Android native function calls proof of concept using eBPF uprobes";
static const char args_doc[] = "";

static const struct argp_option options[] = {
    { "pid",            'p', "PID[,PID...]", 0, "Process ID(s) to inspect",                                                          0 },
    { "package",        'P', "PACKAGE",      0, "Package to spawn",                                                                   0 },
    { "include-module", 'I', "MODULE",       0, "Target module to trace (path, name)",                                                0 },
    { "include",        'i', "FUNCTION",     0, "Target function to trace (regex)",                                                   0 },
    { "verbose",        'v', NULL,           0, "Verbose debug output (modules scanned, symbols matched)",                            0 },
    { "resolve-syms",   'S', NULL,           0, "Symbol resolution mode: resolve and print symbols, no uprobe attachment",            0 },
    { "entry",          'e', "SPEC",         0, "Custom probe: MODULE!FUNC[@OFFSET][(S|V,...)] or MODULE@OFFSET[(S|V,...)]",          0 },
    { "spec-file",      'F', "FILE",         0, "Load custom probe specs from file (one spec per line, # for comments)",              0 },
    { "output",         'o', "FILE",         0, "Export structured JSONL to FILE",                                                    0 },
    { "include-ret",    'r', "FUNCTION",     0, "Return-only probe: function regex (requires -I; attaches uretprobe, no CALL event)", 0 },
    { "caller-only",    'c', NULL,           0, "Print only the direct caller, suppress the rest of the call stack",                  0 },
    { "module",         'm', "NAME",         0, "Activate a tracing module (repeatable). Available: proc-event, execve",              0 },
    { "structured",     'J', 0,              0, "No-op (structured JSONL is now the default -o format)",                             0 },
    { "bufsize",        'b', "MB",           0, "Ring buffer size in MB (default: 4; rounded up to next power of two)",              0 },
    { 0 }
};

struct args {
    pid_t pids[64];
    int pid_count;
    char package_name[256];
    char mod_patterns[32][256];
    int mod_pattern_count;
    char func_patterns[32][256];
    int func_pattern_count;
    bool verbose;
    bool resolve_syms;
    char custom_specs[64][512];
    int custom_spec_count;
    char spec_files[8][256];
    int spec_file_count;
    char output_file[256];
    char func_ret_patterns[32][256];
    int func_ret_pattern_count;
    bool caller_only;
    int  bufmb;          // ring buffer size in MB (0 → default 4)
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
        // Parse comma-separated PIDs
        case 'p': {
            char *tok = strtok(arg, ",");
            while (tok && args->pid_count < 64) {
                args->pids[args->pid_count++] = (pid_t)atoi(tok); 
                tok = strtok(NULL, ",");
            }
            break;
        }

        case 'P':
            copy_str(args->package_name, arg, sizeof(args->package_name));
            break;

        case 'I':
            if (args->mod_pattern_count < 32) {
                copy_str(args->mod_patterns[args->mod_pattern_count++], arg, sizeof(args->mod_patterns[0]));
            }
            break;

        case 'i':
            if (args->func_pattern_count < 32) {
                copy_str(args->func_patterns[args->func_pattern_count++], arg, sizeof(args->func_patterns[0]));
            }
            break;

        case 'v':
            args->verbose = true;
            break;

        case 'S':
            args->resolve_syms = true;
            break;

        case 'e':
            if (args->custom_spec_count < 64)
                copy_str(args->custom_specs[args->custom_spec_count++], arg, 512);
            break;

        case 'F':
            if (args->spec_file_count < 8)
                copy_str(args->spec_files[args->spec_file_count++], arg, 256);
            break;

        case 'o':
            copy_str(args->output_file, arg, sizeof(args->output_file));
            break;

        case 'r':
            if (args->func_ret_pattern_count < 32)
                copy_str(args->func_ret_patterns[args->func_ret_pattern_count++], arg,
                        sizeof(args->func_ret_patterns[0]));
            break;

        case 'c':
            args->caller_only = true;
            break;

        case 'J':
            break; // no-op: structured JSONL is the default -o format

        case 'b': {
            int mb = atoi(arg);
            if (mb < 1) { argp_error(state, "bufsize must be >= 1 MB"); return ARGP_ERR_UNKNOWN; }
            args->bufmb = mb;
            break;
        }

        case 'm': {
            for (int i = 0; all_modules[i]; i++) {
                if (strcmp(arg, all_modules[i]->name) == 0) {
                    for (int j = 0; j < active_module_count; j++) {
                        if (active_modules[j] == all_modules[i])
                            return 0;  // already active, ignore duplicate
                    }
                    if (active_module_count < 16)
                        active_modules[active_module_count++] = all_modules[i];
                    return 0;
                }
            }
            fprintf(stderr, "unknown module '%s'. Available: proc-event, execve, prop-read\n", arg);
            return ARGP_ERR_UNKNOWN;
        }

        // No arguments case
        case ARGP_KEY_END:
            if (args->pid_count > 0 && args->package_name[0] != '\0')
                argp_error(state, "cannot use -p and -P together");
            if (args->pid_count == 0 && args->package_name[0] == '\0')
                argp_usage(state);
            break;
        
        // Default case
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = { options, parse_opts, args_doc, doc, 0, 0, 0 };


// Application UID resolver 
// launch/UID helpers (sh_exec / resolve_uid / get_pid_uid / resolve_component)
// moved to src/common/launch.{c,h} as ares_*; shared with the correlate engine.


// Ctrl-C / SIGTERM → ares_install_stop_handler (cmd_funcs only, not under trace).
// sig_atomic_t so the same type can be shared with the kprobe engine under trace.
static volatile sig_atomic_t exiting = 0;

// Engine state shared across funcs_setup / funcs_run / funcs_teardown.
static struct ring_buffer *g_events_rb;
static char g_funcs_pkg[256];           // package to launch (spawn mode), else ""

// Output sink: shared ares_sink for structured JSONL; stdout/stderr for human text.
static struct ares_sink g_sink;

void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void out_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// Top-level event line, prepends "HH:MM:SS " to stdout.
void ts_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)
{
    time_t t; time(&t);
    char ts_buf[16];
    strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", localtime(&t));
    printf("%s ", ts_buf);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}


// Check module and function pattern match
regex_t mod_re[32];
bool mod_has_slash[32];
regex_t func_re[32];


probe_target_t probe_targets[4096];
int probe_target_count = 0;

static probe_target_t retired_targets[4096];
static int retired_count;

// APK-embedded .so resolution
#define APK_CACHE_MAX  8
#define APK_SO_MAX    256

typedef struct {
    char     name[128];
    uint32_t data_start;
    uint32_t size;
} apk_so_entry_t;

typedef struct {
    char          path[256];
    apk_so_entry_t entries[APK_SO_MAX];
    int           count;
} apk_cache_t;

static apk_cache_t apk_cache[APK_CACHE_MAX];
static int         apk_cache_count;

// Parser module for target resolution
int mod_re_count = 0;
int func_re_count = 0;
regex_t func_ret_re[32];
int func_ret_re_count = 0;
bool verbose = false;
bool resolve_syms = false;
bool caller_only = false;

custom_probe_spec_t custom_probe_specs[64];
int custom_probe_spec_count = 0;


struct bpf_link *probe_links[4096];
struct bpf_link *probe_ret_links[4096];
struct ares_tracer_bpf *skel = NULL;

typedef struct {
    pid_t         pid;
    __u64         addr;
    char          mod[128];
    unsigned long offset;
} caller_cache_entry_t;

#define CALLER_CACHE_SIZE 256
static caller_cache_entry_t caller_cache[CALLER_CACHE_SIZE];
static int caller_cache_count = 0;

static probe_target_t *find_target_by_entry_addr(__u64 entry_addr, pid_t pid, bool *used_fallback)
{
    *used_fallback = false;

    for (int i = 0; i < probe_target_count; i++) {
        if (probe_targets[i].runtime_entry_addr == entry_addr)
            return &probe_targets[i];
    }

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    probe_target_t *result = NULL;

    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f) && !result) {
            unsigned long long start, end, pgoff;
            char perms[5], path[256] = "";

            if (sscanf(line, "%llx-%llx %4s %llx %*s %*d %255s",
                       &start, &end, perms, &pgoff, path) < 4) continue;
            if (entry_addr < start || entry_addr >= end) continue;
            if (!strchr(perms, 'x') || path[0] != '/') continue;

            unsigned long file_offset = (unsigned long)(entry_addr - start) + (unsigned long)pgoff;

            for (int i = 0; i < probe_target_count; i++) {
                if (probe_targets[i].offset == file_offset &&
                    strcmp(probe_targets[i].mod_path, path) == 0) {
                    probe_targets[i].runtime_entry_addr = entry_addr;
                    result = &probe_targets[i];
                    break;
                }
            }
        }
        fclose(f);
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
        }
    }

    return result;
}


// Handle events from ring buffer
static apk_cache_t *apk_cache_get(const char *apk_path)
{
    for (int i = 0; i < apk_cache_count; i++)
        if (strcmp(apk_cache[i].path, apk_path) == 0)
            return &apk_cache[i];
    if (apk_cache_count >= APK_CACHE_MAX) return NULL;

    int fd = open(apk_path, O_RDONLY);
    if (fd < 0) return NULL;

    off_t fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 22) { close(fd); return NULL; }

    // Find EOCD (End of Central Directory), usually at fsize-22, no ZIP comment
    uint8_t buf[22];
    off_t eocd_off = -1;
    lseek(fd, fsize - 22, SEEK_SET);
    if (read(fd, buf, 22) == 22 &&
        buf[0]==0x50 && buf[1]==0x4b && buf[2]==0x05 && buf[3]==0x06) {
        eocd_off = fsize - 22;
    } else {
        off_t limit = fsize - 22 - 65535;
        if (limit < 0) limit = 0;
        for (off_t p = fsize - 23; p >= limit; p--) {
            lseek(fd, p, SEEK_SET);
            if (read(fd, buf, 4) != 4) break;
            if (buf[0]==0x50 && buf[1]==0x4b && buf[2]==0x05 && buf[3]==0x06) {
                lseek(fd, p, SEEK_SET);
                if (read(fd, buf, 22) == 22) { eocd_off = p; break; }
            }
        }
    }
    if (eocd_off < 0) { close(fd); return NULL; }

#define LE16(b,o) ((uint16_t)((b)[(o)] | ((unsigned)(b)[(o)+1]<<8)))
#define LE32(b,o) ((uint32_t)((b)[(o)] | ((unsigned)(b)[(o)+1]<<8) | ((unsigned)(b)[(o)+2]<<16) | ((unsigned)(b)[(o)+3]<<24)))

    uint32_t cd_off      = LE32(buf, 16);
    uint16_t num_entries = LE16(buf, 10);

    apk_cache_t *c = &apk_cache[apk_cache_count];
    copy_str(c->path, apk_path, sizeof(c->path));
    c->count = 0;

    lseek(fd, cd_off, SEEK_SET);
    uint8_t cde[46];
    char fname[256];

    for (int i = 0; i < num_entries && c->count < APK_SO_MAX; i++) {
        if (read(fd, cde, 46) != 46) break;
        if (cde[0]!=0x50 || cde[1]!=0x4b || cde[2]!=0x01 || cde[3]!=0x02) break;

        uint16_t method      = LE16(cde, 10);
        uint32_t comp_size   = LE32(cde, 20);
        uint16_t fname_len   = LE16(cde, 28);
        uint16_t extra_len   = LE16(cde, 30);
        uint16_t comment_len = LE16(cde, 32);
        uint32_t lhdr_off    = LE32(cde, 42);

        uint16_t rlen = fname_len < 255 ? fname_len : 255;
        ssize_t  n    = read(fd, fname, rlen);
        if (n < 0) break;
        fname[n] = '\0';
        off_t skip = (off_t)(fname_len - rlen) + extra_len + comment_len;
        if (skip > 0 && lseek(fd, skip, SEEK_CUR) == (off_t)-1) break;

        // Only stored (uncompressed) .so files under lib/
        if (method != 0) continue;
        if (strncmp(fname, "lib/", 4) != 0) continue;
        const char *base = strrchr(fname, '/');
        base = base ? base + 1 : fname;
        size_t blen = strlen(base);
        if (blen < 4 || strcmp(base + blen - 3, ".so") != 0) continue;

        // Read local file header for actual extra field length, may differ from CD
        off_t cur = lseek(fd, 0, SEEK_CUR);
        uint8_t lfh[30];
        lseek(fd, lhdr_off, SEEK_SET);
        if (read(fd, lfh, 30) == 30 &&
            lfh[0]==0x50 && lfh[1]==0x4b && lfh[2]==0x03 && lfh[3]==0x04) {
            uint32_t data_start = lhdr_off + 30 + LE16(lfh,26) + LE16(lfh,28);
            apk_so_entry_t *e = &c->entries[c->count++];
            copy_str(e->name, base, sizeof(e->name));
            e->data_start = data_start;
            e->size       = comp_size;
        }
        lseek(fd, cur, SEEK_SET);
    }
#undef LE16
#undef LE32

    close(fd);
    apk_cache_count++;
    return c;
}

static bool apk_resolve_offset(const char *apk_path, unsigned long apk_offset,
                                char *so_out, size_t so_sz, unsigned long *so_off_out)
{
    apk_cache_t *c = apk_cache_get(apk_path);
    if (!c) return false;
    for (int i = 0; i < c->count; i++) {
        apk_so_entry_t *e = &c->entries[i];
        if (apk_offset >= e->data_start && apk_offset < e->data_start + e->size) {
            copy_str(so_out, e->name, so_sz);
            *so_off_out = apk_offset - e->data_start;
            return true;
        }
    }
    return false;
}

static int resolve_addr_to_module(pid_t pid, __u64 addr, char *mod_out, size_t mod_sz, unsigned long *offset_out)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;

    char line[512];
    int found = -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end, pgoff;
        char perms[5], path[256] = "";
        if (sscanf(line, "%llx-%llx %4s %llx %*s %*d %255s",
                   &start, &end, perms, &pgoff, path) < 4) continue;
        if (addr < (__u64)start || addr >= (__u64)end) continue;

        unsigned long file_offset = (unsigned long)(addr - start) + (unsigned long)pgoff;
        if (path[0] != '\0' && path[0] != '[') {
            const char *bname = strrchr(path, '/');
            copy_str(mod_out, bname ? bname + 1 : path, mod_sz);
        } else {
            copy_str(mod_out, path[0] ? path : "[anon]", mod_sz);
        }
        *offset_out = file_offset;

        // If the mapping is inside an APK, resolve to the embedded .so
        size_t plen = strlen(path);
        if (plen >= 4 && strcmp(path + plen - 4, ".apk") == 0) {
            char so_name[128];
            unsigned long so_off;
            if (apk_resolve_offset(path, file_offset, so_name, sizeof(so_name), &so_off)) {
                const char *apk_base = strrchr(path, '/');
                apk_base = apk_base ? apk_base + 1 : path;
                char label[512];   // holds the full "apk -> so" before bounded copy
                snprintf(label, sizeof(label), "%s -> %s", apk_base, so_name);
                copy_str(mod_out, label, mod_sz);
                *offset_out = so_off;
            }
        }

        found = 0;
        break;
    }
    fclose(f);
    return found;
}

int lookup_caller(pid_t pid, __u64 addr, char *mod_out, size_t mod_sz, unsigned long *offset_out)
{
    for (int i = 0; i < caller_cache_count; i++) {
        if (caller_cache[i].pid == pid && caller_cache[i].addr == addr) {
            copy_str(mod_out, caller_cache[i].mod, mod_sz);
            *offset_out = caller_cache[i].offset;
            return 0;
        }
    }

    char mod[128] = "";
    unsigned long offset = 0;
    if (resolve_addr_to_module(pid, addr, mod, sizeof(mod), &offset) != 0)
        return -1;

    if (caller_cache_count < CALLER_CACHE_SIZE) {
        caller_cache_entry_t *e = &caller_cache[caller_cache_count++];
        e->pid    = pid;
        e->addr   = addr;
        e->offset = offset;
        copy_str(e->mod, mod, sizeof(e->mod));
    }

    copy_str(mod_out, mod, mod_sz);
    *offset_out = offset;
    return 0;
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

static void apply_custom_specs_for_file(const struct probe_resolve_ctx *ctx,
                                         pid_t pid, const char *path, pid_t uprobe_pid,
                                         unsigned long map_start, unsigned long map_end)
{
    int max = ctx->targets_cap;
    for (int s = 0; s < ctx->custom_spec_count && *ctx->target_count < max; s++) {
        const custom_probe_spec_t *spec = &ctx->custom_specs[s];
        if (!custom_spec_matches_path(spec, path)) continue;

        probe_target_t tgt;
        if (resolve_custom_spec_for_path(pid, path, spec, &tgt) != 0) {
            if (ctx->verbose) err_print("   [err] > custom spec: could not resolve %s!%s in %s\n",
                spec->mod, spec->func[0] ? spec->func : "?", path);
            continue;
        }

        if (is_duplicate(ctx->targets, *ctx->target_count, path, tgt.offset))
            continue;

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
                snprintf(map_files, sizeof(map_files), "/proc/%d/map_files/%lx-%lx",
                         pid, map_start, map_end);
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
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_header *header = data;
    if (data_sz < sizeof(*header)) return 0;
    struct probe_resolve_ctx *rctx = ctx;  // routed via ring_buffer__new (see cmd_funcs)

    // SEAM — structured trace output (deferred; see DOCUMENTATION.md "Unified
    // trace schema"). Today this handler renders human-readable text that the
    // JSONL writer wraps as {ts,stream,tag,message}. The follow-up will, when a
    // structured-JSONL mode is selected, emit one self-describing record per
    // event here using the shared discriminator, e.g.:
    //   {"type":"call",  "pid":..,"tid":..,"module":..,"symbol":..,
    //    "entry_addr":..,"args":[..],"strings":[..],"call_stack":[..]}
    //   {"type":"return","pid":..,"tid":..,"symbol":..,"retval":..,"elapsed_ns":..}
    //   {"type":"map"|"unmap"|"spawn"|"proc_exit"|"execve"|"prop", ...}
    // so ares-mcp can analyze funcs traces with the same field-level tools it
    // uses for "type":"syscall" records. Hook the emitter into each case below.

    if (header->type == ARES_EVENT_MAP) {
        const struct lib_map_event *e = data;
        if (data_sz < sizeof(*e))
            return 0;

        if (verbose) err_print("         [event]   | MMAP : %s\n", e->name);
        char path[256];
        if (ares_libtrace_resolve_path(header->pid, e->start, e->name, path, sizeof(path)) != 0)
            return 0;

        bool mod_matched = mod_matches(path, mod_re, mod_has_slash, mod_re_count);

        // Normal symbol resolution (filtered by -I/-i/-r)
        if (mod_matched && (mod_re_count > 0 || func_ret_re_count > 0)) {
            int prev_count = probe_target_count;
            int max_targets = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])) - prev_count;
            int resolved = resolve_targets_for_file(rctx, header->pid, path,
                                                     (unsigned long)e->start, (unsigned long)e->end,
                                                     probe_targets + prev_count, max_targets);

            if (resolved > 0) {
                probe_target_count += resolved;

                for (int i = prev_count; i < probe_target_count && !exiting; i++) {
                    const char *bname = strrchr(probe_targets[i].mod_path, '/');
                    bname = bname ? bname + 1 : probe_targets[i].mod_path;

                    if (resolve_syms) {
                        ts_print("[sym] > %s!%s @ 0x%lx\\n",
                            bname, probe_targets[i].func_name, probe_targets[i].offset);
                    } else {
                        bool ro = probe_targets[i].ret_only;
                        ts_print("%s > %s!%s @ 0x%lx%s\n",
                            ro ? "[rprobe]" : "[uprobe]",
                            bname, probe_targets[i].func_name, probe_targets[i].offset,
                            probe_targets[i].ret_type != ARG_NONE ? " [+ret]" : "");

                        struct bpf_program *entry_prog = ro
                            ? skel->progs.uprobe_save_only
                            : skel->progs.uprobe_open;
                        probe_links[i] = bpf_program__attach_uprobe(
                            entry_prog, false, -1,
                            probe_targets[i].mod_path, probe_targets[i].offset);

                        if (!probe_links[i]) {
                            char map_files[80];
                            snprintf(map_files, sizeof(map_files), "/proc/%d/map_files/%lx-%lx",
                                     header->pid, (unsigned long)e->start, (unsigned long)e->end);
                            if (access(map_files, F_OK) == 0) {
                                probe_links[i] = bpf_program__attach_uprobe(
                                    entry_prog, false, -1,
                                    map_files, probe_targets[i].offset);
                                if (probe_links[i])
                                    ts_print("[uprobe] > attached via map_files (file deleted): %s!%s\n",
                                              bname, probe_targets[i].func_name);
                                else
                                    err_print("[uprobe] > FAILED: %s!%s\n", bname, probe_targets[i].func_name);
                            } else {
                                ts_print("[uprobe] > MISSED: %s!%s (mapping gone before attach)\n",
                                          bname, probe_targets[i].func_name);
                            }
                        }

                        if (probe_targets[i].ret_type != ARG_NONE || ro) {
                            probe_ret_links[i] = bpf_program__attach_uprobe(
                                skel->progs.uretprobe_open, true, -1,
                                probe_targets[i].mod_path, probe_targets[i].offset);
                            if (!probe_ret_links[i])
                                err_print("[uprobe] > FAILED ret: %s!%s\n",
                                    bname, probe_targets[i].func_name);
                        }
                    }
                }
            }
        }

        // Custom spec resolution (independent of -I/-i filter)
        if (custom_probe_spec_count > 0)
            apply_custom_specs_for_file(rctx, header->pid, path, -1,
                                        (unsigned long)e->start, (unsigned long)e->end);

        return 0;
    }

    if (header->type == ARES_EVENT_UNMAP) {
        const struct lib_unmap_event *e = data;
        if (data_sz < sizeof(*e))
            return 0;

        if (verbose)
            ts_print("[unmap] > PID:%d 0x%llx-0x%llx\n", header->pid,
                     (unsigned long long)e->start, (unsigned long long)e->end);

        return 0;
    }

    // Route module event types (>= ARES_EVENT_SPAWN) to active modules
    if (header->type >= ARES_EVENT_SPAWN) {
        for (int i = 0; i < active_module_count; i++) {
            if (!active_modules[i]->handle_event) continue;
            if (active_modules[i]->handle_event(header, data, data_sz) == 0)
                return 0;
        }
        return 0;
    }

    if (header->type == ARES_EVENT_CALL) {
        if (resolve_syms) return 0;
        const struct event *e = data;

        if (data_sz < sizeof(*e)) return 0;

        bool used_fallback = false;
        probe_target_t *target = find_target_by_entry_addr(e->entry_addr, header->pid, &used_fallback);
        if (target) {
            const char *bname = strrchr(target->mod_path, '/');
            bname = bname ? bname + 1 : target->mod_path;
            ts_print("[event] > [CALL] PID:%d PPID:%d %s!%s @ 0x%lx%s\n",
                e->h.pid, e->ppid, bname, target->func_name, target->offset,
                used_fallback ? " (resolved from known offset)" : "");
            if (g_sink.f) {
                g_sink.jb.len = 0;
                funcs_emit_call(&g_sink.jb, e, bname, target->func_name);
                ares_sink_emit(&g_sink);
            }
        } else {
            ts_print("[event] > [CALL] PID:%d PPID:%d %s!??? @ 0x%llx (unresolved)\n",
                e->h.pid, e->ppid, e->comm, (unsigned long long)e->entry_addr);
            return 0;
        }

        if (target->arg_count >= 0) {
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
                } else {
                    out_print("         [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
                }
            }
            // F arg at [i] followed by relative S at [i+1]: show fully resolved path.
            // Safe for read(F,S,...): buffer is unfilled at CALL time → is_str[i+1]=0.
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
        } else {
            for (int i = 0; i < NUM_ARGS; i++) {
                if (e->is_str[i])
                    out_print("         [event]   | args[%d] \"%s\"\n", i, e->strings[i]);
                else
                    out_print("         [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
            }
        }

        if (e->caller_addr) {
            char caller_mod[128] = "";
            unsigned long caller_off = 0;
            if (lookup_caller(header->pid, e->caller_addr, caller_mod, sizeof(caller_mod), &caller_off) == 0)
                out_print("         [event]   | caller: %s+0x%lx\n", caller_mod, caller_off);
            else
                out_print("         [event]   | caller: 0x%llx\n", (unsigned long long)e->caller_addr);
        }

        if (!caller_only) {
            for (__u32 i = 2; i < e->stack_depth; i++) {
                if (!e->call_stack[i]) break;
                char frame_mod[128] = "";
                unsigned long frame_off = 0;
                if (lookup_caller(header->pid, e->call_stack[i], frame_mod, sizeof(frame_mod), &frame_off) == 0)
                    out_print("         [event]   | #%u %s+0x%lx\n", i, frame_mod, frame_off);
                else
                    out_print("         [event]   | #%u 0x%llx\n", i, (unsigned long long)e->call_stack[i]);
            }
        }
    }

    if (header->type == ARES_EVENT_RETURN) {
        if (resolve_syms) return 0;
        const struct event *e = data;
        if (data_sz < sizeof(*e)) return 0;

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

        // Elapsed time
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

        // Return value: strings[0]/is_str[0] holds the string read from retval pointer
        char retval_buf[MAX_STR_LEN + 4];
        if (ret_type == ARG_STR && e->is_str[0])
            snprintf(retval_buf, sizeof(retval_buf), "\"%s\"", e->strings[0]);
        else
            snprintf(retval_buf, sizeof(retval_buf), "0x%lx", (unsigned long)e->retval);

        ts_print("[event] > [RET]  PID:%d %s!%s @ 0x%lx%s%s -> %s\n",
            header->pid, bname, fname, offset,
            used_fallback ? " (resolved from known offset)" : "",
            elapsed_buf, retval_buf);

        if (g_sink.f) {
            g_sink.jb.len = 0;
            funcs_emit_return(&g_sink.jb, e, bname, fname);
            ares_sink_emit(&g_sink);
        }

        // Output buffer args: args[i+1]/is_str[i+1]/strings[i+1] = re-read of entry arg[i]
        // Only print S-typed args that yielded a string at return time
        if (arg_count >= 0) {
            for (int i = 0; i < arg_count && i < NUM_ARGS - 1; i++) {
                if (arg_types[i] == ARG_STR && e->is_str[i + 1])
                    out_print("         [event]   | args[%d] (out) \"%s\"\n", i, e->strings[i + 1]);
            }
        }

        // Call stack (frame 1 = direct caller printed as "caller:", frames 2+ as "#N")
        __u32 stack_limit = caller_only ? 2 : e->stack_depth;
        for (__u32 i = 1; i < stack_limit; i++) {
            if (!e->call_stack[i]) break;
            char frame_mod[128] = "";
            unsigned long frame_off = 0;
            if (i == 1) {
                if (lookup_caller(header->pid, e->call_stack[i], frame_mod, sizeof(frame_mod), &frame_off) == 0)
                    out_print("         [event]   | caller: %s+0x%lx\n", frame_mod, frame_off);
                else
                    out_print("         [event]   | caller: 0x%llx\n", (unsigned long long)e->call_stack[i]);
            } else {
                if (lookup_caller(header->pid, e->call_stack[i], frame_mod, sizeof(frame_mod), &frame_off) == 0)
                    out_print("         [event]   | #%u %s+0x%lx\n", i, frame_mod, frame_off);
                else
                    out_print("         [event]   | #%u 0x%llx\n", i, (unsigned long long)e->call_stack[i]);
            }
        }
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
    struct args args = {
        .pid_count = 0,
    };
    argp_parse(&argp, argc, argv, 0, NULL, &args);
    verbose = args.verbose;
    resolve_syms = args.resolve_syms;
    caller_only = args.caller_only;

    if (args.output_file[0] != '\0') {
        if (ares_sink_open(&g_sink, args.output_file, "event", /*jsonl=*/1) != 0) {
            fprintf(stderr, "cannot open '%s': %s\n", args.output_file, strerror(errno));
            return 1;
        }
    }

    if (verbose) err_print("  [verb] > mode ON\n");
    if (resolve_syms) ts_print("[info] > symbol resolution mode\n");


    // Resolve application UID (if spawn mode)
    if (args.package_name[0] != '\0') {
        // Remember the package so the caller can launch it after setup returns.
        snprintf(g_funcs_pkg, sizeof(g_funcs_pkg), "%s", args.package_name);
        uid = (rc && rc->uid > 0) ? rc->uid : ares_resolve_uid(args.package_name);
        if (uid < 0) {
            err_print(" [spawn] > could not resolve UID for '%s' (installed? run as root?)\n", args.package_name);
            err = -1;
            goto cleanup;
        }
        ts_print("[spawn] > %s UID %d\n", args.package_name, uid);
    }


    // Prepare regex for pattern matching
    for (int i = 0; i < args.mod_pattern_count; i++) {
        mod_has_slash[i] = strchr(args.mod_patterns[i], '/') != NULL;
        if (regcomp(&mod_re[i], args.mod_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            err_print("   [err] > invalid regex pattern: %s\n", args.mod_patterns[i]);
            err = -1;
            goto cleanup;
        }
        mod_re_count++;
    }
    
    for (int i = 0; i < args.func_pattern_count; i++) {
        if (regcomp(&func_re[i], args.func_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            err_print("   [err] > invalid regex pattern: %s\n", args.func_patterns[i]);
            err = -1;
            goto cleanup;
        }
        func_re_count++;
    }

    for (int i = 0; i < args.func_ret_pattern_count; i++) {
        if (regcomp(&func_ret_re[i], args.func_ret_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            err_print("   [err] > invalid -r regex pattern: %s\n", args.func_ret_patterns[i]);
            err = -1;
            goto cleanup;
        }
        func_ret_re_count++;
    }


    // Parse custom probe specs from -e flags
    for (int i = 0; i < args.custom_spec_count; i++) {
        if (parse_custom_probe_spec(args.custom_specs[i], &custom_probe_specs[custom_probe_spec_count], err_print) == 0)
            custom_probe_spec_count++;
    }

    // Parse custom probe specs from -F spec files
    for (int fi = 0; fi < args.spec_file_count; fi++) {
        FILE *sf = fopen(args.spec_files[fi], "r");
        if (!sf) {
            err_print("   [err] > cannot open spec file '%s': %s\n", args.spec_files[fi], strerror(errno));
            err = -1;
            goto cleanup;
        }
        char sline[512];
        while (fgets(sline, sizeof(sline), sf) && custom_probe_spec_count < 64) {
            char *end = sline + strlen(sline) - 1;
            while (end >= sline && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';
            if (sline[0] == '\0' || sline[0] == '#') continue;
            if (parse_custom_probe_spec(sline, &custom_probe_specs[custom_probe_spec_count], err_print) == 0)
                custom_probe_spec_count++;
        }
        fclose(sf);
    }


    // Open, configure, load, attach BPF skeleton.
    // set_max_entries and set_autoattach must happen after open, before load.
    skel = ares_tracer_bpf__open();
    if (!skel) {
        err_print("   [bpf] > failed to open skeleton\n");
        err = 1;
        goto cleanup;
    }

    bpf_program__set_autoattach(skel->progs.uprobe_open, false);
    bpf_program__set_autoattach(skel->progs.uprobe_save_only, false);
    bpf_program__set_autoattach(skel->progs.uretprobe_open, false);
    for (int i = 0; all_modules[i]; i++)
        if (all_modules[i]->pre_attach)
            all_modules[i]->pre_attach(skel);

    {
        int bufmb = args.bufmb > 0 ? args.bufmb : 4;
        size_t bufbytes = ares_round_pow2((unsigned long)bufmb << 20);
        bpf_map__set_max_entries(skel->maps.events_rb, (unsigned int)bufbytes);
        if (ares_tracer_bpf__load(skel)) {
            err_print("   [bpf] > failed to load skeleton\n");
            ares_tracer_bpf__destroy(skel);
            skel = NULL;
            err = 1;
            goto cleanup;
        }
        ts_print("  [bpf] > ring buffer: %zu MB\n", bufbytes >> 20);
    }

    err = ares_tracer_bpf__attach(skel);
    if (err) {
        err_print("   [bpf] > failed to attach (uprobe_mmap in kallsyms?)\n");
        goto cleanup;
    }

    for (int i = 0; i < active_module_count; i++) {
        if (active_modules[i]->attach) {
            int r = active_modules[i]->attach(skel);
            if (r == -1) { err = -1; goto cleanup; }
            if (r == -2)
                ts_print("[warn]  > module '%s' running in degraded mode — some events will be missing\n",
                         active_modules[i]->name);
        }
    }
    elf_version(EV_CURRENT);

    // Resolution context: points at the file-scope regex/target/spec state, built
    // after all counts are finalized. Routed into handle_event via ring_buffer__new.
    struct probe_resolve_ctx rctx = {
        .mod_re = mod_re, .mod_has_slash = mod_has_slash, .mod_re_count = mod_re_count,
        .func_re = func_re, .func_re_count = func_re_count,
        .func_ret_re = func_ret_re, .func_ret_re_count = func_ret_re_count,
        .targets = probe_targets, .target_count = &probe_target_count,
        .targets_cap = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])),
        .custom_specs = custom_probe_specs, .custom_spec_count = custom_probe_spec_count,
        .verbose = verbose,
        .log = err_print,
    };

    g_events_rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, &rctx, NULL);
    if (!g_events_rb) {
        err = -1;
        err_print("    [rb] > failed to create ring buffer\n");
        goto cleanup;
    }


    // Find and resolve symbols in PID attach mode / spawn mode, then attach uprobes
    if (args.pid_count > 0) {
        if (mod_re_count > 0 || func_re_count > 0) {
            for (int i = 0; i < args.pid_count; i++) {
                ts_print("[probe] > resolving targets for PID %d\n", args.pids[i]);
                int resolved = resolve_targets(
                    &rctx,
                    args.pids[i],
                    probe_targets + probe_target_count,
                    sizeof(probe_targets) / sizeof(probe_targets[0]) - probe_target_count
                );
                if (resolved > 0) probe_target_count += resolved;
            }

            if (probe_target_count == 0 && !resolve_syms && custom_probe_spec_count == 0) {
                err_print(" [probe] > no trace targets found\n");
                err = -1;
                goto cleanup;
            }
        }

        __u8 one = 1;
        for (int i = 0; i < args.pid_count; i++) {
            int pid_uid = ares_get_pid_uid(args.pids[i]);
            if (pid_uid <= 0) {
                err_print(" [probe] > could not resolve UID for PID %d\n", args.pids[i]);
                continue;
            }
            __u32 vuid = (__u32)pid_uid;
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
                err_print(" [probe] > failed to set target UID %d: %s\n", pid_uid, strerror(errno));
                goto cleanup;
            }
            ts_print("[probe] > PID %d UID %d\n", args.pids[i], pid_uid);
        }

        if (mod_re_count > 0 || func_re_count > 0) {
            for (int i = 0; i < probe_target_count && !exiting; i++) {
                const char *bname = strrchr(probe_targets[i].mod_path, '/');
                bname = bname ? bname + 1 : probe_targets[i].mod_path;

                if (resolve_syms) {
                    ts_print("[sym] > %s!%s @ 0x%lx\n",
                        bname, probe_targets[i].func_name, probe_targets[i].offset);
                } else {
                    bool ro = probe_targets[i].ret_only;
                    ts_print("%s > %s!%s @ 0x%lx%s\n",
                        ro ? "[rprobe]" : "[uprobe]",
                        bname, probe_targets[i].func_name, probe_targets[i].offset,
                        probe_targets[i].ret_type != ARG_NONE ? " [+ret]" : "");
                    struct bpf_program *entry_prog = ro
                        ? skel->progs.uprobe_save_only
                        : skel->progs.uprobe_open;
                    probe_links[i] = bpf_program__attach_uprobe(
                        entry_prog, false,
                        probe_targets[i].pid,
                        probe_targets[i].mod_path,
                        probe_targets[i].offset);
                    if (!probe_links[i]) {
                        err_print("[uprobe] > FAILED: %s!%s\n", bname, probe_targets[i].func_name);
                        err = -1;
                        goto cleanup;
                    }
                    if (probe_targets[i].ret_type != ARG_NONE || ro) {
                        probe_ret_links[i] = bpf_program__attach_uprobe(
                            skel->progs.uretprobe_open, true,
                            probe_targets[i].pid,
                            probe_targets[i].mod_path,
                            probe_targets[i].offset);
                        if (!probe_ret_links[i])
                            err_print("[uprobe] > FAILED ret: %s!%s\n",
                                      bname, probe_targets[i].func_name);
                    }
                }
            }
        }

        // Apply custom probe specs for each PID
        if (custom_probe_spec_count > 0) {
            for (int p = 0; p < args.pid_count; p++) {
                char maps_path[64];
                snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", args.pids[p]);
                FILE *mf = fopen(maps_path, "r");
                if (!mf) continue;
                char mline[512];
                while (fgets(mline, sizeof(mline), mf)) {
                    char perms[5], mpath[256] = "";
                    if (sscanf(mline, "%*x-%*x %4s %*x %*s %*d %255s", perms, mpath) < 1) continue;
                    if (mpath[0] != '/') continue;
                    if (!strchr(perms, 'x')) continue;
                    apply_custom_specs_for_file(&rctx, args.pids[p], mpath, args.pids[p], 0, 0);
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

        if (mod_re_count > 0 || func_re_count > 0 || func_ret_re_count > 0) {
            int prev = probe_target_count;
            int max = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])) - prev;
            int resolved = resolve_targets(&rctx, zygote_pid, probe_targets + prev, max);
            ts_print("[zygote] > resolve_targets -> %d symbols\n", resolved);
            if (resolved > 0) {
                probe_target_count += resolved;
                for (int i = prev; i < probe_target_count && !exiting; i++) {
                    const char *bname = strrchr(probe_targets[i].mod_path, '/');
                    bname = bname ? bname + 1 : probe_targets[i].mod_path;
                    if (resolve_syms) {
                        ts_print("[sym] > %s!%s @ 0x%lx\\n",
                            bname, probe_targets[i].func_name, probe_targets[i].offset);
                    } else {
                        bool ro = probe_targets[i].ret_only;
                        ts_print("%s > %s!%s @ 0x%lx%s\n",
                            ro ? "[rprobe]" : "[uprobe]",
                            bname, probe_targets[i].func_name, probe_targets[i].offset,
                            probe_targets[i].ret_type != ARG_NONE ? " [+ret]" : "");
                        struct bpf_program *entry_prog = ro
                            ? skel->progs.uprobe_save_only
                            : skel->progs.uprobe_open;
                        probe_links[i] = bpf_program__attach_uprobe(
                            entry_prog, false, -1,
                            probe_targets[i].mod_path, probe_targets[i].offset);
                        if (!probe_links[i])
                            err_print("[uprobe] > FAILED: %s!%s\n",
                                bname, probe_targets[i].func_name);
                        if (probe_targets[i].ret_type != ARG_NONE || ro) {
                            probe_ret_links[i] = bpf_program__attach_uprobe(
                                skel->progs.uretprobe_open, true, -1,
                                probe_targets[i].mod_path, probe_targets[i].offset);
                            if (!probe_ret_links[i])
                                err_print("[uprobe] > FAILED ret: %s!%s\n",
                                    bname, probe_targets[i].func_name);
                        }
                    }
                }
                if (!resolve_syms)
                    ts_print("[zygote] > attached %d uprobes for pre-loaded libs\n",
                              probe_target_count - prev);
            }
        }

        if (custom_probe_spec_count > 0) {
            char cmaps[64];
            snprintf(cmaps, sizeof(cmaps), "/proc/%d/maps", zygote_pid);
            FILE *cf = fopen(cmaps, "r");
            if (cf) {
                char cline[512];
                while (fgets(cline, sizeof(cline), cf)) {
                    char cperms[5], cpath[256] = "";
                    if (sscanf(cline, "%*x-%*x %4s %*x %*s %*d %255s", cperms, cpath) < 1) continue;
                    if (cpath[0] != '/') continue;
                    if (!strchr(cperms, 'x')) continue;
                    apply_custom_specs_for_file(&rctx, zygote_pid, cpath, -1, 0, 0);
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
    int err = 0;
    int ticks = 0;
    while (!*stop) {
        err = ring_buffer__poll(g_events_rb, 1);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) { err_print("   [err] > ring buffer poll error: %d\n", err); break; }
        if (g_sink.f && ++ticks >= 200) { ticks = 0; ares_sink_flush(&g_sink); } // ~200ms periodic flush
    }

    for (int i = 0; i < active_module_count; i++)
        if (active_modules[i]->print_summary)
            active_modules[i]->print_summary();

    return err < 0 ? -err : 0;
}

void funcs_teardown(void)
{
    if (g_events_rb) {
        ring_buffer__free(g_events_rb);
        g_events_rb = NULL;
    }

    for (int i = 0; i < probe_target_count; i++) {
        if (probe_links[i])     bpf_link__destroy(probe_links[i]);
        if (probe_ret_links[i]) bpf_link__destroy(probe_ret_links[i]);
    }
    for (int i = 0; i < active_module_count; i++)
        if (active_modules[i]->detach)
            active_modules[i]->detach();
    for (int i = 0; i < mod_re_count; i++)      regfree(&mod_re[i]);
    for (int i = 0; i < func_re_count; i++)     regfree(&func_re[i]);
    for (int i = 0; i < func_ret_re_count; i++) regfree(&func_ret_re[i]);

    if (skel) {
        ares_drops_report(ares_drops_read(bpf_map__fd(skel->maps.dropped)), 0);
        ares_tracer_bpf__destroy(skel);
        skel = NULL;
    }
    ares_sink_close(&g_sink);
    ares_sink_report(&g_sink);
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
        ts_print("[spawn] > launching %s\n", g_funcs_pkg);
        if (ares_launch_app(g_funcs_pkg, NULL) != 0) {
            err_print(" [spawn] > failed to launch %s\n", g_funcs_pkg);
            funcs_teardown();
            return 1;
        }
    }

    funcs_run(&exiting);
    funcs_teardown();
    return 0;
}