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
#include <fnmatch.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ares-tracer.h"
#include "ares-tracer.skel.h"
#include "modules/module.h"
#include "so_repair.h"
#include "common/lib_trace.h"

extern char **environ;

#define ARG_STR  0
#define ARG_VAL  1
#define ARG_NONE 2  // no return probe for this target
#define ARG_FD   3  // fd argument; resolved to path via /proc/PID/fd/<n> at display time

static const ares_module_t *const all_modules[] = {
    &module_proc_event,
    &module_execve,
    &module_prop_read,
    NULL,
};
static const ares_module_t *active_modules[16];
static int active_module_count = 0;

// Argument parser module using argp.h
const char *argp_program_version = "ares-tracer 1.0";
const char *argp_program_bug_address = "<vincentferdinand.k@gmail.com>";
static const char doc[] = "Android native function calls proof of concept using eBPF uprobes";
static const char args_doc[] = "";

static const struct argp_option options[] = {
    { "pid", 'p', "PID[,PID...]", 0, "Process ID(s) to inspect" },
    { "package", 'P', "PACKAGE", 0, "Package to spawn" },
    { "include-module", 'I', "MODULE", 0, "Target module to trace (path, name)" },
    { "include", 'i', "FUNCTION", 0, "Target function to trace (regex)" },
    { "verbose", 'v', NULL, 0, "Verbose debug output (modules scanned, symbols matched)" },
    { "resolve-syms", 'S', NULL, 0, "Symbol resolution mode: resolve and print symbols, no uprobe attachment" },
    { "entry", 'e', "SPEC", 0, "Custom probe: MODULE!FUNC[@OFFSET][(S|V,...)] or MODULE@OFFSET[(S|V,...)]" },
    { "spec-file", 'F', "FILE", 0, "Load custom probe specs from file (one spec per line, # for comments)" },
    { "output", 'o', "FILE", 0, "Export output to file (.csv -> CSV, .jsonl/.ndjson -> JSONL)" },
    { "include-ret", 'r', "FUNCTION", 0, "Return-only probe: function regex (requires -I; attaches uretprobe, no CALL event)" },
    { "caller-only", 'c', NULL, 0, "Print only the direct caller, suppress the rest of the call stack" },
    { "module", 'm', "NAME", 0, "Activate a tracing module (repeatable). Available: proc-event, execve" },
    { "dump", 'D', "PATTERN", 0, "Dump matching module from /proc/PID/mem to .bin file when mapped (repeatable, up to 8)" },
    { "dump-dir", 'd', "DIR", 0, "Output directory for -D dumps (default: /data/local/tmp)" },
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
    char dump_modules[8][256];
    int  dump_module_count;
    char dump_dir[256];
};

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
            strncpy(args->package_name, arg, sizeof(args->package_name) - 1);
            args->package_name[sizeof(args->package_name) - 1] = '\0';
            break;

        case 'I':
            if (args->mod_pattern_count < 32) {
                strncpy(args->mod_patterns[args->mod_pattern_count++], arg, sizeof(args->mod_patterns[0]) - 1);
            }
            break;

        case 'i':
            if (args->func_pattern_count < 32) {
                strncpy(args->func_patterns[args->func_pattern_count++], arg, sizeof(args->func_patterns[0]) - 1);
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
                strncpy(args->custom_specs[args->custom_spec_count++], arg, 511);
            break;

        case 'F':
            if (args->spec_file_count < 8)
                strncpy(args->spec_files[args->spec_file_count++], arg, 255);
            break;

        case 'o':
            strncpy(args->output_file, arg, sizeof(args->output_file) - 1);
            break;

        case 'r':
            if (args->func_ret_pattern_count < 32)
                strncpy(args->func_ret_patterns[args->func_ret_pattern_count++], arg,
                        sizeof(args->func_ret_patterns[0]) - 1);
            break;

        case 'c':
            args->caller_only = true;
            break;

        case 'D':
            if (args->dump_module_count < 8)
                strncpy(args->dump_modules[args->dump_module_count++], arg,
                        sizeof(args->dump_modules[0]) - 1);
            break;

        case 'd':
            strncpy(args->dump_dir, arg, sizeof(args->dump_dir) - 1);
            break;

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

static const struct argp argp = { options, parse_opts, args_doc, doc };


// Application UID resolver 
static int sh_exec(const char *cmd, char *out, size_t outsz)
{
    int pipefd[2] = { -1, -1 };
	if (out != NULL) {
		out[0] = '\0';
		if (pipe(pipefd) != 0)
			return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		if (out != NULL) { close(pipefd[0]); close(pipefd[1]); }
		return -1;
	}

    if (pid == 0) {
		if (out != NULL) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[0]);
			close(pipefd[1]);
		} else {
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
		}
		char *argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, NULL };
		execve("/system/bin/sh", argv, environ);
		_exit(127);
	}

    if (out != NULL) {
		close(pipefd[1]);
		size_t off = 0;
		ssize_t n;
		while (off + 1 < outsz && (n = read(pipefd[0], out + off, outsz - 1 - off)) > 0)
			off += (size_t)n;
		out[off] = '\0';
		close(pipefd[0]);
	}

	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return status;
}

static int resolve_uid(const char *pkg)
{
	const char *roots[] = { "/data/data/%s", "/data/user/0/%s", "/data/user_de/0/%s" };
	for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		char path[256];
		snprintf(path, sizeof(path), roots[i], pkg);
		struct stat st;
		if (stat(path, &st) == 0)
			return (int)st.st_uid;
	}
	return -1;
}

static int get_pid_uid(pid_t pid)
{
	char path[64], line[128];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	int uid = -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned int ruid;
		if (sscanf(line, "Uid:\t%u", &ruid) == 1) {
			uid = (int)ruid;
			break;
		}
	}
	fclose(f);
	return uid;
}

static int resolve_component(const char *pkg, char *out, size_t outsz)
{
	char cmd[512], buf[1024];
	snprintf(cmd, sizeof(cmd), "cmd package resolve-activity --brief %s", pkg);
	if (sh_exec(cmd, buf, sizeof(buf)) < 0)
		return -1;

	out[0] = '\0';
	char *save = NULL;
	for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (strchr(line, '/') && strstr(line, pkg))     // Get the last "pkg/..." line
			snprintf(out, outsz, "%s", line);
	}
	return out[0] ? 0 : -1;
}


// eBPF debug print
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // if (level == LIBBPF_DEBUG) return 0;
    // return vfprintf(stderr, format, args);
    return 0; // Suppress output
}


// Ctrl + C handler
static volatile bool exiting = false;
static volatile int sig_count = 0;

static void sig_handler(int sig)
{
    exiting = true;
    if (++sig_count > 1)
        _exit(1);
}


// CSV output and print wrappers
static FILE *g_csv = NULL;
static FILE *g_jsonl = NULL;
static void jsonl_write(const char *stream, const char *buf);

static void csv_write(const char *stream, const char *buf)
{
    char msg[4096];
    strncpy(msg, buf, sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = '\0';
    size_t len = strlen(msg);
    while (len > 0 && (msg[len - 1] == '\n' || msg[len - 1] == '\r'))
        msg[--len] = '\0';
    if (len == 0) return;

    char tag[32] = "";
    const char *p = msg;
    while (*p == ' ') p++;
    if (*p == '[') {
        const char *end = strchr(p + 1, ']');
        if (end) {
            size_t tlen = (size_t)(end - p - 1);
            if (tlen < sizeof(tag)) { memcpy(tag, p + 1, tlen); tag[tlen] = '\0'; }
        }
    }

    time_t t; time(&t);
    struct tm *tmi = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", tmi);

    fprintf(g_csv, "%s,%s,%s,\"", ts, stream, tag);
    for (const char *c = msg; *c; c++) {
        if (*c == '"') fputc('"', g_csv);
        fputc(*c, g_csv);
    }
    fputs("\"\n", g_csv);
    fflush(g_csv);
}

void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void out_print(const char *fmt, ...)
{
    va_list ap1, ap2;
    va_start(ap1, fmt);
    va_copy(ap2, ap1);
    vprintf(fmt, ap1);
    va_end(ap1);
    if (g_csv || g_jsonl) {
        char buf[4096];
        vsnprintf(buf, sizeof(buf), fmt, ap2);
        if (g_csv)   csv_write("out", buf);
        if (g_jsonl) jsonl_write("out", buf);
    }
    va_end(ap2);
}

void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...)
{
    va_list ap1, ap2;
    va_start(ap1, fmt);
    va_copy(ap2, ap1);
    FILE *se = stderr;
    vfprintf(se, fmt, ap1);
    va_end(ap1);
    if (g_csv || g_jsonl) {
        char buf[4096];
        vsnprintf(buf, sizeof(buf), fmt, ap2);
        if (g_csv)   csv_write("err", buf);
        if (g_jsonl) jsonl_write("err", buf);
    }
    va_end(ap2);
}

static int csv_open(const char *path)
{
    g_csv = fopen(path, "w");
    if (!g_csv) {
        err_print("   [err] > cannot open CSV output '%s': %s\n", path, strerror(errno));
        return -1;
    }
    fputs("timestamp,stream,tag,message\n", g_csv);
    fflush(g_csv);
    return 0;
}

static void csv_close(void)
{
    if (g_csv) { fclose(g_csv); g_csv = NULL; }
}

static void json_fwrite_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            default:
                if ((unsigned char)*s < 0x20)
                    fprintf(f, "\\u%04x", (unsigned char)*s);
                else
                    fputc(*s, f);
        }
    }
    fputc('"', f);
}

static void jsonl_write(const char *stream, const char *buf)
{
    char msg[4096];
    strncpy(msg, buf, sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = '\0';
    size_t len = strlen(msg);
    while (len > 0 && (msg[len-1] == '\n' || msg[len-1] == '\r'))
        msg[--len] = '\0';
    if (len == 0) return;

    char tag[32] = "";
    const char *p = msg;
    while (*p == ' ') p++;
    if (*p == '[') {
        const char *end = strchr(p + 1, ']');
        if (end) {
            size_t tlen = (size_t)(end - p - 1);
            if (tlen < sizeof(tag)) { memcpy(tag, p + 1, tlen); tag[tlen] = '\0'; }
        }
    }

    time_t t; time(&t);
    struct tm *tmi = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tmi);

    fprintf(g_jsonl, "{\"ts\":\"%s\",\"stream\":\"%s\",\"tag\":\"%s\",\"message\":",
            ts, stream, tag);
    json_fwrite_str(g_jsonl, msg);
    fputs("}\n", g_jsonl);
    fflush(g_jsonl);
}

static int jsonl_open(const char *path)
{
    g_jsonl = fopen(path, "w");
    if (!g_jsonl) {
        err_print("   [err] > cannot open JSONL output '%s': %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static void jsonl_close(void)
{
    if (g_jsonl) { fclose(g_jsonl); g_jsonl = NULL; }
}

// Top-level event line, prepends "HH:MM:SS  " to stdout; CSV receives message only.
void ts_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)
{
    time_t t; time(&t);
    char ts_buf[16];
    strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", localtime(&t));
    printf("%s ", ts_buf);
    va_list ap1, ap2;
    va_start(ap1, fmt);
    va_copy(ap2, ap1);
    vprintf(fmt, ap1);
    va_end(ap1);
    if (g_csv || g_jsonl) {
        char buf[4096];
        vsnprintf(buf, sizeof(buf), fmt, ap2);
        if (g_csv)   csv_write("out", buf);
        if (g_jsonl) jsonl_write("out", buf);
    }
    va_end(ap2);
}


// Check module and function pattern match
regex_t mod_re[32];
bool mod_has_slash[32];
regex_t func_re[32];

typedef struct {
    pid_t pid;
    char mod_path[256];
    char func_name[256];
    unsigned long offset;
    __u64 runtime_entry_addr;
    int arg_count;       // -1 = use BPF heuristic, 0-8 manual spec
    uint8_t arg_types[8];
    uint8_t ret_type;    // ARG_VAL, ARG_STR, or ARG_NONE (no return probe)
    bool ret_only;       // true = -r match: uprobe_save_only + uretprobe, no CALL event
} probe_target_t;

typedef struct {
    char mod[256];
    char func[256];
    unsigned long offset; // 0 = resolve from symbol name
    int arg_count;
    uint8_t arg_types[8];
    uint8_t ret_type;    // ARG_VAL, ARG_STR, or ARG_NONE
    bool ret_only;       // true when '>' present but no '()': uretprobe only, no CALL event
} custom_probe_spec_t;

static bool mod_matches(const char *full_path, regex_t *re, bool *has_slash, int count)
{
    if (count == 0) return true;
    const char *target;

    for (int i = 0; i < count; i++) {
        if (has_slash[i]) {
            target = full_path;
        } else {
            target = strrchr(full_path, '/');
            target = target ? target + 1 : full_path;
        }
        if (regexec(&re[i], target, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}

static bool func_matches(const char *func_name, regex_t *re, int count)
{
    if (count == 0) return true;

    for (int i = 0; i < count; i++) {
        if (regexec(&re[i], func_name, 0, NULL, 0) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_duplicate(probe_target_t *targets, int count, const char *mod_path, unsigned long offset)
{
    for (int i = 0; i < count; i++) {
        if (targets[i].offset == offset && strcmp(targets[i].mod_path, mod_path) == 0) {
            return true;
        }
    }
    return false;
}


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

static regex_t dump_module_re[8];
static int     dump_module_count = 0;
static char    dump_dir[256] = "/data/local/tmp";

static bool dump_pattern_matches(const char *path)
{
    const char *bname = strrchr(path, '/');
    bname = bname ? bname + 1 : path;
    for (int i = 0; i < dump_module_count; i++) {
        if (regexec(&dump_module_re[i], bname, 0, NULL, 0) == 0)
            return true;
    }
    return false;
}

#define DUMP_CHUNK (4 * 1024 * 1024)
static char dump_chunk_buf[DUMP_CHUNK];
static char dump_zero_page[4096];  // zero-fill buffer for unmapped gaps

typedef struct { uint64_t start; uint64_t end; } vma_range_t;

// Collect all VMA ranges in /proc/PID/maps that belong to `path`.
// If apk_off_lo < apk_off_hi, only include segments whose file offset (bytes)
// falls within [apk_off_lo, apk_off_hi) — used to isolate one embedded SO.
// Returns segment count, -1 on maps open failure, 0 if path not found.
static int collect_segments(pid_t pid, const char *path,
                             vma_range_t *out, int max_segs,
                             uint64_t apk_off_lo, uint64_t apk_off_hi)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f)
        return -1;

    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) && count < max_segs) {
        unsigned long long seg_start, seg_end, pgoff;
        char seg_path[256] = "";
        if (sscanf(line, "%llx-%llx %*s %llx %*s %*d %255s",
                   &seg_start, &seg_end, &pgoff, seg_path) < 3)
            continue;
        if (strcmp(seg_path, path) != 0) continue;
        if (apk_off_lo < apk_off_hi &&
            (pgoff < apk_off_lo || pgoff >= apk_off_hi)) continue;
        out[count].start = (uint64_t)seg_start;
        out[count].end   = (uint64_t)seg_end;
        count++;
    }
    fclose(f);
    return count;
}

// Dump the full in-memory image of a library from /proc/PID/mem.
// Scans /proc/PID/maps for all segments belonging to `path` to get the full
// ELF range (including non-executable segments the BPF never fires on).
// Falls back to [fb_start, fb_end] if maps scanning fails or finds nothing.
// Unmapped gaps between segments are zero-filled.
static void dump_library_full(pid_t pid, const char *path, const char *bname,
                               uint64_t fb_start, uint64_t fb_end,
                               uint64_t apk_off_lo, uint64_t apk_off_hi)
{
    vma_range_t segs[32];
    int nseg = collect_segments(pid, path, segs, 32, apk_off_lo, apk_off_hi);

    uint64_t min_start, max_end;
    if (nseg <= 0) {
        // Maps already gone (transient lib) or open failed — fall back to BPF range
        min_start = fb_start;
        max_end   = fb_end;
        nseg      = 0;
    } else {
        min_start = segs[0].start;
        max_end   = segs[0].end;
        for (int i = 1; i < nseg; i++) {
            if (segs[i].start < min_start) min_start = segs[i].start;
            if (segs[i].end   > max_end)   max_end   = segs[i].end;
        }
    }

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int memfd = open(mem_path, O_RDONLY);
    if (memfd < 0) {
        err_print(" [dump] > FAILED open %s: %s\n", mem_path, strerror(errno));
        return;
    }

    char outfile[320];
    snprintf(outfile, sizeof(outfile), "%s/%s_%d_0x%llx.bin",
             dump_dir, bname, pid, (unsigned long long)min_start);
    int outfd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outfd < 0) {
        err_print(" [dump] > FAILED create %s: %s\n", outfile, strerror(errno));
        close(memfd);
        return;
    }

    uint64_t written = 0;
    uint64_t pos     = min_start;

    while (pos < max_end) {
        // Read page by page so we can detect and zero-fill individual gaps
        size_t want = (max_end - pos < 4096) ? (size_t)(max_end - pos) : 4096;
        if (lseek(memfd, (off_t)pos, SEEK_SET) == (off_t)-1)
            break;
        ssize_t n = read(memfd, dump_chunk_buf, want);
        if (n > 0) {
            write(outfd, dump_chunk_buf, (size_t)n);
            written += (uint64_t)n;
            pos     += (uint64_t)n;
        } else {
            // Unmapped gap — zero-fill one page and continue
            write(outfd, dump_zero_page, want);
            written += want;
            pos     += want;
        }
    }

    close(memfd);
    close(outfd);

    if (written == 0) {
        ts_print(" [dump] > MISSED: %s PID:%d (all mappings gone before read)\n", bname, pid);
        return;
    }

    if (nseg > 0)
        ts_print(" [dump] > %s PID:%d 0x%llx-0x%llx -> %s (%llu bytes, %d segments)\n",
                 bname, pid,
                 (unsigned long long)min_start, (unsigned long long)max_end,
                 outfile, (unsigned long long)written, nseg);
    else
        ts_print(" [dump] > %s PID:%d 0x%llx-0x%llx -> %s (%llu bytes, fallback)\n",
                 bname, pid,
                 (unsigned long long)min_start, (unsigned long long)max_end,
                 outfile, (unsigned long long)written);

    repair_dumped_so(outfile, min_start);
}

static int resolve_targets(pid_t pid, probe_target_t *targets, int max_targets)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    if (verbose) err_print("  [scan] > opening %s\n", maps_path);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        err_print("  [scan] > fopen %s failed: %s\n", maps_path, strerror(errno));
        return -1;
    }

    char line[512];
    int count = 0;
    int n_rx = 0, n_matched = 0;

    while (fgets(line, sizeof(line), f) && count < max_targets) {
        char perms[5], path[256] = "";

        if (sscanf(line, "%*x-%*x %4s %*x %*s %*d %255s", perms, path) < 1) continue;
        if (path[0] != '/') continue;
        if (!strchr(perms, 'x')) continue;

        if (verbose) err_print("  [maps] > rx[%d]: %s\n", n_rx, path);
        n_rx++;

        if (!mod_matches(path, mod_re, mod_has_slash, mod_re_count)) {
            if (verbose) err_print("  [maps]   | skip (no -I match)\n");
            continue;
        }
        if (verbose) err_print("  [maps]   | match! opening ELF...\n");
        n_matched++;

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            if (verbose) err_print("  [scan] > skip (open failed: %s)\n", strerror(errno));
            continue;
        }
        if (verbose) err_print("  [maps]   | ELF fd=%d, parsing sections...\n", fd);

        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf) {
            if (verbose) err_print("  [scan]   | skip (not a valid ELF)\n");
            close(fd);
            continue;
        }

        Elf_Scn *scn = NULL;

        while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_targets) {
            GElf_Shdr shdr;
            if (!gelf_getshdr(scn, &shdr)) continue;

            if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
            if (shdr.sh_entsize == 0) continue;

            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data) continue;

            int num_symbols = shdr.sh_size / shdr.sh_entsize;
            if (verbose) err_print("  [scan]   | %s: %d symbols\n",
                shdr.sh_type == SHT_SYMTAB ? "SHT_SYMTAB" : "SHT_DYNSYM", num_symbols);

            for (int i = 0; i < num_symbols && count < max_targets; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);

                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
                if (sym.st_value == 0) continue;

                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || name[0] == '\0') continue;
                bool entry_match = func_matches(name, func_re, func_re_count);
                // When -r given but not -i, don't apply default "match all" for entry probes
                if (func_re_count == 0 && func_ret_re_count > 0) entry_match = false;
                bool ret_match = func_ret_re_count > 0 &&
                                 func_matches(name, func_ret_re, func_ret_re_count);
                if (!entry_match && !ret_match) continue;

                if (verbose) err_print(" [match] > %s!%s @ 0x%lx%s\n",
                    path, name, (unsigned long)sym.st_value,
                    (!entry_match && ret_match) ? " (ret-only)" : "");

                if (!is_duplicate(probe_targets, probe_target_count + count, path, (unsigned long)sym.st_value)) {
                    targets[count].pid = pid;
                    strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                    strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1);
                    targets[count].offset = (unsigned long)sym.st_value;
                    targets[count].arg_count = -1;
                    memset(targets[count].arg_types, 0, sizeof(targets[count].arg_types));
                    targets[count].ret_only = !entry_match && ret_match;
                    targets[count].ret_type = ret_match ? ARG_VAL : ARG_NONE;
                    count++;
                }
            }
        }
        elf_end(elf);
        close(fd);
        if (verbose) err_print("  [maps]   | ELF done, symbols so far: %d\n", count);
    }

    if (verbose) err_print("  [scan] > done: %d rx entries, %d matched, %d found\n",
        n_rx, n_matched, count);
    fclose(f);
    return count;
}

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
    strncpy(c->path, apk_path, sizeof(c->path) - 1);
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
            strncpy(e->name, base, sizeof(e->name) - 1);
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
            strncpy(so_out, e->name, so_sz - 1);
            so_out[so_sz - 1] = '\0';
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
            strncpy(mod_out, bname ? bname + 1 : path, mod_sz - 1);
            mod_out[mod_sz - 1] = '\0';
        } else {
            strncpy(mod_out, path[0] ? path : "[anon]", mod_sz - 1);
            mod_out[mod_sz - 1] = '\0';
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
                snprintf(mod_out, mod_sz, "%s -> %s", apk_base, so_name);
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
            strncpy(mod_out, caller_cache[i].mod, mod_sz - 1);
            mod_out[mod_sz - 1] = '\0';
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
        strncpy(e->mod, mod, sizeof(e->mod) - 1);
        e->mod[sizeof(e->mod) - 1] = '\0';
    }

    strncpy(mod_out, mod, mod_sz - 1);
    mod_out[mod_sz - 1] = '\0';
    *offset_out = offset;
    return 0;
}

static int resolve_targets_for_file(pid_t pid, const char *path,
                                     unsigned long map_start, unsigned long map_end,
                                     probe_target_t *targets, int max_targets)
{
    if (verbose) err_print("  [scan] > %s (map event)\n", path);

    int fd = open(path, O_RDONLY);
    if (fd < 0 && map_start && map_end) {
        char map_files[80];
        snprintf(map_files, sizeof(map_files), "/proc/%d/map_files/%lx-%lx",
                 pid, map_start, map_end);
        fd = open(map_files, O_RDONLY);
        if (fd >= 0 && verbose)
            err_print("  [scan] > opened via map_files (file deleted from fs)\n");
    }
    if (fd < 0) {
        if (verbose) err_print("  [scan] > skip (open failed: %s)\n", strerror(errno));
        return -1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        if (verbose) err_print("  [scan]   | skip (not a valid ELF)\n");
        close(fd);
        return -1;
    }

    int count = 0;
    Elf_Scn *scn = NULL;

    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_targets) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;

        int num_symbols = shdr.sh_size / shdr.sh_entsize;
        if (verbose) err_print("  [scan]   | %s: %d symbols\n",
            shdr.sh_type == SHT_SYMTAB ? "SHT_SYMTAB" : "SHT_DYNSYM", num_symbols);

        for (int i = 0; i < num_symbols && count < max_targets; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);

            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') continue;

            bool entry_match = func_matches(name, func_re, func_re_count);
            if (func_re_count == 0 && func_ret_re_count > 0) entry_match = false;
            bool ret_match = func_ret_re_count > 0 &&
                             func_matches(name, func_ret_re, func_ret_re_count);
            if (!entry_match && !ret_match) continue;

            if (verbose) err_print(" [match] > %s!%s @ 0x%lx%s\n",
                path, name, (unsigned long)sym.st_value,
                (!entry_match && ret_match) ? " (ret-only)" : "");

            if (!is_duplicate(probe_targets, probe_target_count + count, path, (unsigned long)sym.st_value)) {
                targets[count].pid = pid;
                strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1);
                targets[count].offset = (unsigned long)sym.st_value;
                targets[count].arg_count = -1;
                memset(targets[count].arg_types, 0, sizeof(targets[count].arg_types));
                targets[count].ret_only = !entry_match && ret_match;
                targets[count].ret_type = ret_match ? ARG_VAL : ARG_NONE;
                count++;
            }
        }
    }
    elf_end(elf);
    close(fd);

    return count;
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

static bool custom_spec_matches_path(const custom_probe_spec_t *spec, const char *path)
{
    if (strchr(spec->mod, '/'))
        return strstr(path, spec->mod) != NULL;
    const char *bname = strrchr(path, '/');
    bname = bname ? bname + 1 : path;
    if (strchr(spec->mod, '*') || strchr(spec->mod, '?'))
        return fnmatch(spec->mod, bname, 0) == 0;
    return strcmp(bname, spec->mod) == 0;
}

static int parse_custom_probe_spec(const char *input, custom_probe_spec_t *out)
{
    memset(out, 0, sizeof(*out));
    out->arg_count = -1;
    out->ret_type  = ARG_NONE;

    char buf[512];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    // Strip '>rettype' suffix (outside any parentheses): e.g. "libc.so!fgets(S,V,V)>V"
    {
        bool in_paren = false;
        for (char *p = buf; *p; p++) {
            if (*p == '(') in_paren = true;
            else if (*p == ')') in_paren = false;
            else if (*p == '>' && !in_paren) {
                *p = '\0';
                char *rp = p + 1;
                while (*rp == ' ') rp++;
                if (*rp == 'S' || *rp == 's')      out->ret_type = ARG_STR;
                else if (*rp == 'V' || *rp == 'v') out->ret_type = ARG_VAL;
                else {
                    err_print("   [err] > unknown return type '%c' in spec: %s\n", *rp, input);
                    return -1;
                }
                break;
            }
        }
    }

    char *paren = strchr(buf, '(');
    if (paren) {
        *paren = '\0';
        char *close = strchr(paren + 1, ')');
        if (!close) {
            err_print("   [err] > malformed spec (unclosed '('): %s\n", input);
            return -1;
        }
        *close = '\0';
        out->arg_count = 0;
        char *save = NULL;
        for (char *tok = strtok_r(paren + 1, ",", &save);
             tok && out->arg_count < 8;
             tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ') tok++;
            if (*tok == 'S' || *tok == 's')
                out->arg_types[out->arg_count++] = ARG_STR;
            else if (*tok == 'V' || *tok == 'v')
                out->arg_types[out->arg_count++] = ARG_VAL;
            else if (*tok == 'F' || *tok == 'f')
                out->arg_types[out->arg_count++] = ARG_FD;
            else {
                err_print("   [err] > unknown arg type '%c' in spec: %s\n", *tok, input);
                return -1;
            }
        }
    }

    char *bang = strchr(buf, '!');
    if (bang) {
        *bang = '\0';
        strncpy(out->mod, buf, sizeof(out->mod) - 1);
        char *at = strchr(bang + 1, '@');
        if (at) {
            *at = '\0';
            strncpy(out->func, bang + 1, sizeof(out->func) - 1);
            out->offset = strtoul(at + 1, NULL, 0);
        } else {
            strncpy(out->func, bang + 1, sizeof(out->func) - 1);
        }
    } else {
        char *at = strchr(buf, '@');
        if (!at) {
            err_print("   [err] > invalid spec (need '!' or '@'): %s\n", input);
            return -1;
        }
        *at = '\0';
        strncpy(out->mod, buf, sizeof(out->mod) - 1);
        out->offset = strtoul(at + 1, NULL, 0);
    }

    if (out->mod[0] == '\0') {
        err_print("   [err] > empty module in spec: %s\n", input);
        return -1;
    }
    if (out->func[0] == '\0' && out->offset == 0) {
        err_print("   [err] > spec needs function name or offset: %s\n", input);
        return -1;
    }
    // '>rettype' without '()': return-only probe (no CALL event, like -r)
    // '()>rettype' or '(args)>rettype': paired (CALL + RET)
    out->ret_only = (out->ret_type != ARG_NONE && out->arg_count == -1);
    return 0;
}

static int resolve_custom_spec_for_path(pid_t pid, const char *path,
                                         const custom_probe_spec_t *spec,
                                         probe_target_t *out)
{
    out->pid = pid;
    strncpy(out->mod_path, path, sizeof(out->mod_path) - 1);
    out->mod_path[sizeof(out->mod_path) - 1] = '\0';
    strncpy(out->func_name, spec->func, sizeof(out->func_name) - 1);
    out->func_name[sizeof(out->func_name) - 1] = '\0';
    out->runtime_entry_addr = 0;
    out->arg_count = spec->arg_count;
    memcpy(out->arg_types, spec->arg_types, sizeof(spec->arg_types));
    out->ret_type = spec->ret_type;
    out->ret_only = spec->ret_only;

    if (spec->offset > 0) {
        out->offset = spec->offset;
        return 0;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return -1; }

    int found = -1;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL && found < 0) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;
        int num = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < num && found < 0; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (name && strcmp(name, spec->func) == 0) {
                out->offset = (unsigned long)sym.st_value;
                found = 0;
            }
        }
    }
    elf_end(elf);
    close(fd);
    return found;
}

static void apply_custom_specs_for_file(pid_t pid, const char *path, pid_t uprobe_pid,
                                         unsigned long map_start, unsigned long map_end)
{
    int max = (int)(sizeof(probe_targets) / sizeof(probe_targets[0]));
    for (int s = 0; s < custom_probe_spec_count && probe_target_count < max; s++) {
        const custom_probe_spec_t *spec = &custom_probe_specs[s];
        if (!custom_spec_matches_path(spec, path)) continue;

        probe_target_t tgt;
        if (resolve_custom_spec_for_path(pid, path, spec, &tgt) != 0) {
            if (verbose) err_print("   [err] > custom spec: could not resolve %s!%s in %s\n",
                spec->mod, spec->func[0] ? spec->func : "?", path);
            continue;
        }

        if (is_duplicate(probe_targets, probe_target_count, path, tgt.offset))
            continue;

        int idx = probe_target_count;
        probe_targets[idx] = tgt;
        probe_links[idx] = NULL;
        probe_target_count++;

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

        if (dump_module_count > 0) {
            const char *dump_label = NULL;
            char apk_so_name[128] = "";
            bool do_dump = false;
            uint64_t apk_off_lo = 0, apk_off_hi = 0;

            size_t plen = strlen(path);
            if (plen >= 4 && strcmp(path + plen - 4, ".apk") == 0) {
                unsigned long so_off;
                if (apk_resolve_offset(path, (unsigned long)e->pgoff << 12,
                                       apk_so_name, sizeof(apk_so_name), &so_off)
                    && dump_pattern_matches(apk_so_name)) {
                    do_dump = true;
                    dump_label = apk_so_name;
                    // Narrow segment collection to this SO's byte range in the APK
                    // so dump_library_full doesn't span segments of other embedded SOs.
                    apk_cache_t *ac = apk_cache_get(path);
                    if (ac) {
                        for (int k = 0; k < ac->count; k++) {
                            if (strcmp(ac->entries[k].name, apk_so_name) == 0) {
                                apk_off_lo = ac->entries[k].data_start;
                                apk_off_hi = ac->entries[k].data_start + ac->entries[k].size;
                                break;
                            }
                        }
                    }
                }
            } else if (dump_pattern_matches(path)) {
                do_dump = true;
                const char *bname = strrchr(path, '/');
                dump_label = bname ? bname + 1 : path;
            }

            if (do_dump)
                dump_library_full(header->pid, path, dump_label, e->start, e->end,
                                  apk_off_lo, apk_off_hi);
        }

        // Normal symbol resolution (filtered by -I/-i/-r)
        if (mod_matched && (mod_re_count > 0 || func_ret_re_count > 0)) {
            int prev_count = probe_target_count;
            int max_targets = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])) - prev_count;
            int resolved = resolve_targets_for_file(header->pid, path,
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
            apply_custom_specs_for_file(header->pid, path, -1,
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
int cmd_funcs(int argc, char **argv)
{
    // Boilerplate setup
    struct ring_buffer *events_rb = NULL;
    int err = 0;
    int uid = -1;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    

    // Argument parsing
    struct args args = {
        .pid_count = 0,
    };
    argp_parse(&argp, argc, argv, 0, NULL, &args);
    verbose = args.verbose;
    resolve_syms = args.resolve_syms;
    caller_only = args.caller_only;

    if (args.dump_dir[0] != '\0')
        strncpy(dump_dir, args.dump_dir, sizeof(dump_dir) - 1);
    for (int i = 0; i < args.dump_module_count; i++) {
        if (regcomp(&dump_module_re[dump_module_count], args.dump_modules[i], REG_EXTENDED | REG_NOSUB) == 0)
            dump_module_count++;
        else
            fprintf(stderr, "invalid dump pattern: %s\n", args.dump_modules[i]);
    }

    if (args.output_file[0] != '\0') {
        const char *ext = strrchr(args.output_file, '.');
        const char *slash = strrchr(args.output_file, '/');
        bool is_jsonl = ext && (!slash || ext > slash) &&
                        (strcmp(ext, ".jsonl") == 0 || strcmp(ext, ".ndjson") == 0);
        if ((is_jsonl ? jsonl_open(args.output_file) : csv_open(args.output_file)) != 0)
            return 1;
    }

    if (verbose) err_print("  [verb] > mode ON\n");
    if (resolve_syms) ts_print("[info] > symbol resolution mode\n");


    // Resolve application UID (if spawn mode)
    if (args.package_name[0] != '\0') {
        uid = resolve_uid(args.package_name);
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
        if (parse_custom_probe_spec(args.custom_specs[i], &custom_probe_specs[custom_probe_spec_count]) == 0)
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
            if (parse_custom_probe_spec(sline, &custom_probe_specs[custom_probe_spec_count]) == 0)
                custom_probe_spec_count++;
        }
        fclose(sf);
    }


    // Open, load, attach BPF skeleton
    skel = ares_tracer_bpf__open_and_load();
    if (!skel) {
        err_print("   [bpf] > failed to load skeleton\n");
        err = 1;
        goto cleanup;
    }

    bpf_program__set_autoattach(skel->progs.uprobe_open, false);
    bpf_program__set_autoattach(skel->progs.uprobe_save_only, false);
    bpf_program__set_autoattach(skel->progs.uretprobe_open, false);
    for (int i = 0; all_modules[i]; i++)
        if (all_modules[i]->pre_attach)
            all_modules[i]->pre_attach(skel);

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

    events_rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, NULL, NULL);
    if (!events_rb) {
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
            int pid_uid = get_pid_uid(args.pids[i]);
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
                    apply_custom_specs_for_file(args.pids[p], mpath, args.pids[p], 0, 0);
                }
                fclose(mf);
            }
        }
    } else {
        char cmd[512], package_activity[256];

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
            int resolved = resolve_targets(zygote_pid, probe_targets + prev, max);
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
                    apply_custom_specs_for_file(zygote_pid, cpath, -1, 0, 0);
                }
                fclose(cf);
            }
        }

        // Force stop the package first
        snprintf(cmd, sizeof(cmd), "am force-stop %s", args.package_name);
        sh_exec(cmd, NULL, 0);

        // Make sure package is gone
        snprintf(cmd, sizeof(cmd), "pidof %s", args.package_name);
        for (int i = 0; i < 30; i++) {
            char pid_buf[32] = "";
            sh_exec(cmd, pid_buf, sizeof(pid_buf));
            if (pid_buf[0] == '\0') break;
            usleep(100000);
        }

        // Resolve main activity
        if (resolve_component(args.package_name, package_activity, sizeof(package_activity)) != 0) {
            err_print(" [spawn] > failed to resolve component for %s\n", args.package_name);
            err = -1;
            goto cleanup;
        }

        // Update target UIDs for BPF program (filtering)
        __u8 one = 1;
        __u32 vuid = (__u32)uid;
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
            err_print(" [spawn] > failed to set target UID: %s\n", strerror(errno));
            goto cleanup;
        }

        ts_print("[spawn] > launching %s\n", args.package_name);
        snprintf(cmd, sizeof(cmd), "am start -S -n %s", package_activity);
        if (sh_exec(cmd, NULL, 0) != 0) {
            err_print(" [spawn] > failed to start %s\n", args.package_name);
            err = -1;
            goto cleanup;
        }
    }

    while (!exiting) {
        err = ring_buffer__poll(events_rb, 1);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) { err_print("   [err] > ring buffer poll error: %d\n", err); break; }
    }

    for (int i = 0; i < active_module_count; i++)
        if (active_modules[i]->print_summary)
            active_modules[i]->print_summary();

    // Cleanup mechanism
    cleanup:
        ring_buffer__free(events_rb);

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

        ares_tracer_bpf__destroy(skel);
        csv_close();
        jsonl_close();

        return err < 0 ? -err : 0;
}