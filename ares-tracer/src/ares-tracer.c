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

extern char **environ;

#define ARG_STR 0
#define ARG_VAL 1

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
    { "list-libs", 'L', NULL, 0, "Library detection mode: list loaded/unloaded libs, no uprobe attachment" },
    { "resolve-syms", 'S', NULL, 0, "Symbol resolution mode: resolve and print symbols, no uprobe attachment" },
    { "entry", 'e', "SPEC", 0, "Custom probe: MODULE!FUNC[@OFFSET][(S|V,...)] or MODULE@OFFSET[(S|V,...)]" },
    { "spec-file", 'F', "FILE", 0, "Load custom probe specs from file (one spec per line, # for comments)" },
    { "output", 'o', "FILE", 0, "Export all output to CSV file" },
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
    bool list_libs;
    bool resolve_syms;
    char custom_specs[64][512];
    int custom_spec_count;
    char spec_files[8][256];
    int spec_file_count;
    char output_file[256];
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

        case 'L':
            args->list_libs = true;
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
	char cmd[256], buf[1024];
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
    return 0; // Suppress temporarily
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

static void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out_print(const char *fmt, ...)
{
    va_list ap1, ap2;
    va_start(ap1, fmt);
    va_copy(ap2, ap1);
    vprintf(fmt, ap1);
    va_end(ap1);
    if (g_csv) {
        char buf[4096];
        vsnprintf(buf, sizeof(buf), fmt, ap2);
        csv_write("out", buf);
    }
    va_end(ap2);
}

static void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void err_print(const char *fmt, ...)
{
    va_list ap1, ap2;
    va_start(ap1, fmt);
    va_copy(ap2, ap1);
    FILE *se = stderr;
    vfprintf(se, fmt, ap1);
    va_end(ap1);
    if (g_csv) {
        char buf[4096];
        vsnprintf(buf, sizeof(buf), fmt, ap2);
        csv_write("err", buf);
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
    int arg_count;       // -1 = use BPF heuristic; 0-8 = typed
    uint8_t arg_types[8];
} probe_target_t;

typedef struct {
    char mod[256];
    char func[256];
    unsigned long offset; // 0 = resolve from symbol name
    int arg_count;
    uint8_t arg_types[8];
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
static bool verbose = false;
static bool list_libs = false;
static bool resolve_syms = false;

custom_probe_spec_t custom_probe_specs[64];
int custom_probe_spec_count = 0;

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
                if (!func_matches(name, func_re, func_re_count)) continue;

                if (verbose) err_print(" [match] > %s!%s @ 0x%lx\n",
                    path, name, (unsigned long)sym.st_value);

                if (!is_duplicate(probe_targets, probe_target_count + count, path, (unsigned long)sym.st_value)) {
                    targets[count].pid = pid;
                    strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                    strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1);
                    targets[count].offset = (unsigned long)sym.st_value;
                    targets[count].arg_count = -1;
                    memset(targets[count].arg_types, 0, sizeof(targets[count].arg_types));
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
static int find_path_in_maps(pid_t pid, unsigned long long start, char *out, size_t outsz)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        if (verbose) err_print("  [scan] > fopen %s failed: %s\n", maps_path, strerror(errno));
        return -1;
    }

    // Read /proc/PID/maps line by line then parse
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char perms[5], path[256] = "";
        unsigned long long start_addr;

        if (sscanf(line, "%llx-%*x %4s %*x %*s %*d %255s", &start_addr, perms, path) < 2) continue;
        
        if (start_addr == start) {
            strncpy(out, path, outsz - 1);
            out[outsz - 1] = '\0';
            
            fclose(f);
            return 0;
        }
    }   

    fclose(f);
    return -1;
}

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

    // Find EOCD (End of Central Directory): usually at fsize-22, no ZIP comment
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
        lseek(fd, (fname_len - rlen) + extra_len + comment_len, SEEK_CUR);

        // Only stored (uncompressed) .so files under lib/
        if (method != 0) continue;
        if (strncmp(fname, "lib/", 4) != 0) continue;
        const char *base = strrchr(fname, '/');
        base = base ? base + 1 : fname;
        size_t blen = strlen(base);
        if (blen < 4 || strcmp(base + blen - 3, ".so") != 0) continue;

        // Read local file header for actual extra field length (may differ from CD)
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

static int lookup_caller(pid_t pid, __u64 addr, char *mod_out, size_t mod_sz, unsigned long *offset_out)
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
            if (!func_matches(name, func_re, func_re_count)) continue;

            if (verbose) err_print(" [match] > %s!%s @ 0x%lx\n",
                path, name, (unsigned long)sym.st_value);

            if (!is_duplicate(probe_targets, probe_target_count + count, path, (unsigned long)sym.st_value)) {
                targets[count].pid = pid;
                strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1);
                targets[count].offset = (unsigned long)sym.st_value;
                targets[count].arg_count = -1;
                memset(targets[count].arg_types, 0, sizeof(targets[count].arg_types));
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

    char buf[512];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

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
    if (list_libs) return;

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
            out_print("  [sym] > %s!%s @ 0x%lx\n", bname, label, tgt.offset);
        } else {
            out_print(" [spec] > %s!%s @ 0x%lx\n", bname, label, tgt.offset);
            probe_links[idx] = bpf_program__attach_uprobe(
                skel->progs.uprobe_open, false, uprobe_pid, path, tgt.offset);
            if (!probe_links[idx] && map_start && map_end) {
                char map_files[80];
                snprintf(map_files, sizeof(map_files), "/proc/%d/map_files/%lx-%lx",
                         pid, map_start, map_end);
                if (access(map_files, F_OK) == 0) {
                    probe_links[idx] = bpf_program__attach_uprobe(
                        skel->progs.uprobe_open, false, uprobe_pid, map_files, tgt.offset);
                    if (probe_links[idx])
                        out_print(" [spec] > attached via map_files (file deleted): %s!%s\n",
                                  bname, label);
                    else
                        err_print(" [spec] > FAILED: %s!%s\n", bname, label);
                } else {
                    out_print(" [spec] > MISSED: %s!%s (mapping gone before attach)\n",
                              bname, label);
                }
            } else if (!probe_links[idx]) {
                err_print(" [spec] > FAILED: %s!%s\n", bname, label);
            }
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_header *header = data;
    if (data_sz < sizeof(*header)) return 0;

    // Get current time
    struct tm *tm;
    char ts[32];
    time_t t;
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (header->type == ARES_EVENT_MAP) {
        const struct map_event *e = data;
        if (data_sz < sizeof(*e)) 
            return 0;
        
        if (verbose) err_print(" [event]   | MMAP : %s\n", e->name);
        // Get full path from /proc/PID/maps based on start addreess
        char path[256];
        if (find_path_in_maps(header->pid, e->start, path, sizeof(path)) != 0)
            return 0;

        bool mod_matched = mod_matches(path, mod_re, mod_has_slash, mod_re_count);

        if (list_libs) {
            if (mod_matched) {
                size_t plen = strlen(path);
                if (plen >= 4 && strcmp(path + plen - 4, ".apk") == 0) {
                    char so_name[128];
                    unsigned long so_off;
                    if (apk_resolve_offset(path, (unsigned long)e->pgoff << 12, so_name, sizeof(so_name), &so_off))
                        out_print("   [map] > %s -> %s\n", path, so_name);
                    else
                        out_print("   [map] > %s\n", path);
                } else {
                    out_print("   [map] > %s\n", path);
                }
            }
            return 0;
        }

        // Normal symbol resolution (filtered by -I/-i; skipped when no -I given)
        if (mod_matched && mod_re_count > 0) {
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
                        out_print("  [sym] > %s!%s @ 0x%lx\n",
                            bname, probe_targets[i].func_name, probe_targets[i].offset);
                    } else {
                        out_print("[uprobe] > %s!%s @ 0x%lx\n",
                            bname, probe_targets[i].func_name, probe_targets[i].offset);

                        probe_links[i] = bpf_program__attach_uprobe(
                            skel->progs.uprobe_open, false, -1,
                            probe_targets[i].mod_path, probe_targets[i].offset);

                        if (!probe_links[i]) {
                            char map_files[80];
                            snprintf(map_files, sizeof(map_files), "/proc/%d/map_files/%lx-%lx",
                                     header->pid, (unsigned long)e->start, (unsigned long)e->end);
                            if (access(map_files, F_OK) == 0) {
                                probe_links[i] = bpf_program__attach_uprobe(
                                    skel->progs.uprobe_open, false, -1,
                                    map_files, probe_targets[i].offset);
                                if (probe_links[i])
                                    out_print("[uprobe] > attached via map_files (file deleted): %s!%s\n",
                                              bname, probe_targets[i].func_name);
                                else
                                    err_print("[uprobe] > FAILED: %s!%s\n", bname, probe_targets[i].func_name);
                            } else {
                                out_print("[uprobe] > MISSED: %s!%s (mapping gone before attach)\n",
                                          bname, probe_targets[i].func_name);
                            }
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
        const struct map_event *e = data;
        if (data_sz < sizeof(*e))
            return 0;

        if (verbose) err_print(" [event]   | UNMAP: %s\n", e->name);

        if (list_libs) return 0;

        int removed = 0;
        for (int i = probe_target_count - 1; i >= 0; i--) {
            const char *bname = strrchr(probe_targets[i].mod_path, '/');
            bname = bname ? bname + 1 : probe_targets[i].mod_path;
            if (strcmp(bname, e->name) != 0)
                continue;

            if (probe_links[i])
                bpf_link__destroy(probe_links[i]);

            if (retired_count < 4096)
                retired_targets[retired_count++] = probe_targets[i];

            probe_targets[i] = probe_targets[probe_target_count - 1];
            probe_links[i]   = probe_links[probe_target_count - 1];
            probe_links[probe_target_count - 1] = NULL;
            probe_target_count--;
            removed++;
        }

        if (removed > 0 && !resolve_syms)
            out_print(" [unmap] > %s (%d probes removed)\n", e->name, removed);

        return 0;
    }

    if (header->type == ARES_EVENT_CALL) {
        if (list_libs || resolve_syms) return 0;
        const struct event *e = data;

        if (data_sz < sizeof(*e)) return 0;

        bool used_fallback = false;
        probe_target_t *target = find_target_by_entry_addr(e->entry_addr, header->pid, &used_fallback);
        if (target) {
            const char *bname = strrchr(target->mod_path, '/');
            bname = bname ? bname + 1 : target->mod_path;
            out_print(" [event] > [CALL] %s PID:%d PPID:%d %s!%s @ 0x%lx%s\n",
                ts, e->h.pid, e->ppid, bname, target->func_name, target->offset,
                used_fallback ? " (resolved from known offset)" : "");
        } else {
            out_print(" [event] > [CALL] %s PID:%d PPID:%d %s!??? @ 0x%llx (unresolved)\n",
                ts, e->h.pid, e->ppid, e->comm, (unsigned long long)e->entry_addr);
            return 0;
        }

        if (e->caller_addr) {
            char caller_mod[128] = "";
            unsigned long caller_off = 0;
            if (lookup_caller(header->pid, e->caller_addr, caller_mod, sizeof(caller_mod), &caller_off) == 0)
                out_print(" [event]   | caller: %s+0x%lx\n", caller_mod, caller_off);
            else
                out_print(" [event]   | caller: 0x%llx\n", (unsigned long long)e->caller_addr);
        }

        for (__u32 i = 2; i < e->stack_depth; i++) {
            if (!e->call_stack[i]) break;
            char frame_mod[128] = "";
            unsigned long frame_off = 0;
            if (lookup_caller(header->pid, e->call_stack[i], frame_mod, sizeof(frame_mod), &frame_off) == 0)
                out_print(" [event]   | #%u %s+0x%lx\n", i, frame_mod, frame_off);
            else
                out_print(" [event]   | #%u 0x%llx\n", i, (unsigned long long)e->call_stack[i]);
        }

        if (target->arg_count >= 0) {
            for (int i = 0; i < target->arg_count; i++) {
                if (target->arg_types[i] == ARG_STR) {
                    if (e->is_str[i])
                        out_print(" [event]   | args[%d] \"%s\"\n", i, e->strings[i]);
                    else
                        out_print(" [event]   | args[%d] 0x%lx (?str)\n", i, (unsigned long)e->args[i]);
                } else {
                    out_print(" [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
                }
            }
        } else {
            for (int i = 0; i < NUM_ARGS; i++) {
                if (e->is_str[i])
                    out_print(" [event]   | args[%d] \"%s\"\n", i, e->strings[i]);
                else
                    out_print(" [event]   | args[%d] 0x%lx\n", i, (unsigned long)e->args[i]);
            }
        }
    }

    return 0;
}


// La driver function 
int main(int argc, char **argv)
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
    list_libs = args.list_libs;
    resolve_syms = args.resolve_syms;

    if (args.output_file[0] != '\0' && csv_open(args.output_file) != 0) {
        return 1;
    }

    if (verbose) err_print("  [verb] > mode ON\n");
    if (list_libs) out_print("  [info] > library detection mode\n");
    if (resolve_syms) out_print("  [info] > symbol resolution mode\n");


    // Resolve application UID (if spawn mode)
    if (args.package_name[0] != '\0') {
        uid = resolve_uid(args.package_name);
        if (uid < 0) {
            err_print(" [spawn] > could not resolve UID for '%s' (installed? run as root?)\n", args.package_name);
            err = -1;
            goto cleanup;
        }
        out_print(" [spawn] > %s UID %d\n", args.package_name, uid);
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
    err = ares_tracer_bpf__attach(skel);
    if (err) {
        err_print("   [bpf] > failed to attach (uprobe_mmap in kallsyms?)\n");
        goto cleanup;
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
        if (!list_libs && mod_re_count > 0) {
            for (int i = 0; i < args.pid_count; i++) {
                out_print(" [probe] > resolving targets for PID %d\n", args.pids[i]);
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
            out_print(" [probe] > PID %d UID %d\n", args.pids[i], pid_uid);
        }

        if (!list_libs && mod_re_count > 0) {
            for (int i = 0; i < probe_target_count && !exiting; i++) {
                const char *bname = strrchr(probe_targets[i].mod_path, '/');
                bname = bname ? bname + 1 : probe_targets[i].mod_path;

                if (resolve_syms) {
                    out_print("  [sym] > %s!%s @ 0x%lx\n",
                        bname, probe_targets[i].func_name, probe_targets[i].offset);
                } else {
                    out_print("[uprobe] > %s!%s @ 0x%lx\n",
                        bname, probe_targets[i].func_name, probe_targets[i].offset);
                    probe_links[i] = bpf_program__attach_uprobe(
                        skel->progs.uprobe_open,
                        false,
                        probe_targets[i].pid,
                        probe_targets[i].mod_path,
                        probe_targets[i].offset
                    );
                    if (!probe_links[i]) {
                        err_print("[uprobe] > FAILED: %s!%s\n", bname, probe_targets[i].func_name);
                        err = -1;
                        goto cleanup;
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
        out_print("[zygote] > scanning pre-loaded libs from PID %d\n", zygote_pid);

        if (!list_libs && mod_re_count > 0) {
            int prev = probe_target_count;
            int max = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])) - prev;
            int resolved = resolve_targets(zygote_pid, probe_targets + prev, max);
            out_print("[zygote] > resolve_targets -> %d symbols\n", resolved);
            if (resolved > 0) {
                probe_target_count += resolved;
                for (int i = prev; i < probe_target_count && !exiting; i++) {
                    const char *bname = strrchr(probe_targets[i].mod_path, '/');
                    bname = bname ? bname + 1 : probe_targets[i].mod_path;
                    if (resolve_syms) {
                        out_print("  [sym] > %s!%s @ 0x%lx\n",
                            bname, probe_targets[i].func_name, probe_targets[i].offset);
                    } else {
                        out_print("[uprobe] > %s!%s @ 0x%lx\n",
                            bname, probe_targets[i].func_name, probe_targets[i].offset);
                        probe_links[i] = bpf_program__attach_uprobe(
                            skel->progs.uprobe_open, false, -1,
                            probe_targets[i].mod_path, probe_targets[i].offset);
                        if (!probe_links[i])
                            err_print("[uprobe] > FAILED: %s!%s\n",
                                bname, probe_targets[i].func_name);
                    }
                }
                if (!resolve_syms)
                    out_print("[zygote] > attached %d uprobes for pre-loaded libs\n",
                              probe_target_count - prev);
            }
        }

        if (!list_libs && custom_probe_spec_count > 0) {
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

        out_print(" [spawn] > launching %s\n", args.package_name);
        snprintf(cmd, sizeof(cmd), "am start -S -n %s", package_activity);
        if (sh_exec(cmd, NULL, 0) != 0) {
            err_print(" [spawn] > failed to start %s\n", args.package_name);
            err = -1;
            goto cleanup;
        }
    }

    while (!exiting) {
        err = ring_buffer__poll(events_rb, 50);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) { err_print("   [err] > ring buffer poll error: %d\n", err); break; }
    }


    // Cleanup mechanism
    cleanup:
        ring_buffer__free(events_rb);

        for (int i = 0; i < probe_target_count; i++) 
            if (probe_links[i]) bpf_link__destroy(probe_links[i]);
        for (int i = 0; i < mod_re_count; i++) regfree(&mod_re[i]);
        for (int i = 0; i < func_re_count; i++) regfree(&func_re[i]);

        ares_tracer_bpf__destroy(skel);
        csv_close();

        return err < 0 ? -err : 0;
}