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
#include <sys/ptrace.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ares-tracer.h"
#include "ares-tracer.skel.h"

extern char **environ;


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
} probe_target_t;

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

// Parser module for target resolution
int mod_re_count = 0;
int func_re_count = 0;
static bool verbose = false;
static bool list_libs = false;

static int resolve_targets(pid_t pid, probe_target_t *targets, int max_targets)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    if (verbose) fprintf(stderr, "  [scan] > opening %s\n", maps_path);

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "  [scan] > fopen %s failed: %s\n", maps_path, strerror(errno));
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

        if (verbose) fprintf(stderr, "  [maps] > rx[%d]: %s\n", n_rx, path);
        n_rx++;

        if (!mod_matches(path, mod_re, mod_has_slash, mod_re_count)) {
            if (verbose) fprintf(stderr, "  [maps]   | skip (no -I match)\n");
            continue;
        }
        if (verbose) fprintf(stderr, "  [maps]   | match! opening ELF...\n");
        n_matched++;

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            if (verbose) fprintf(stderr, "  [scan] > skip (open failed: %s)\n", strerror(errno));
            continue;
        }
        if (verbose) fprintf(stderr, "  [maps]   | ELF fd=%d, parsing sections...\n", fd);

        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf) {
            if (verbose) fprintf(stderr, "  [scan]   | skip (not a valid ELF)\n");
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
            if (verbose) fprintf(stderr, "  [scan]   | %s: %d symbols\n",
                shdr.sh_type == SHT_SYMTAB ? "SHT_SYMTAB" : "SHT_DYNSYM", num_symbols);

            for (int i = 0; i < num_symbols && count < max_targets; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);

                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
                if (sym.st_value == 0) continue;

                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || name[0] == '\0') continue;
                if (!func_matches(name, func_re, func_re_count)) continue;

                if (verbose) fprintf(stderr, " [match] > %s!%s @ 0x%lx\n",
                    path, name, (unsigned long)sym.st_value);

                if (!is_duplicate(probe_targets, probe_target_count + count, path, (unsigned long)sym.st_value)) {
                    targets[count].pid = pid;
                    strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                    strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1);
                    targets[count].offset = (unsigned long)sym.st_value;
                    count++;
                }
            }
        }
        elf_end(elf);
        close(fd);
        if (verbose) fprintf(stderr, "  [maps]   | ELF done, symbols so far: %d\n", count);
    }

    if (verbose) fprintf(stderr, "  [scan] > done: %d rx entries, %d matched, %d found\n",
        n_rx, n_matched, count);
    fclose(f);
    return count;
}

struct bpf_link *probe_links[4096];
struct ares_tracer_bpf *skel = NULL;
static pid_t g_zygote_pid = -1;

typedef struct {
    pid_t         pid;
    __u64         addr;
    char          mod[128];
    unsigned long offset;
} caller_cache_entry_t;

#define CALLER_CACHE_SIZE 256
static caller_cache_entry_t caller_cache[CALLER_CACHE_SIZE];
static int caller_cache_count = 0;

static probe_target_t *find_target_by_entry_addr(__u64 entry_addr, pid_t pid)
{
    for (int i = 0; i < probe_target_count; i++) {
        if (probe_targets[i].runtime_entry_addr == entry_addr)
            return &probe_targets[i];
    }

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return NULL;

    char line[512];
    probe_target_t *result = NULL;

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
    return result;
}


// Handle events from ring buffer
static int find_path_in_maps(pid_t pid, unsigned long long start, char *out, size_t outsz)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "  [scan] > fopen %s failed: %s\n", maps_path, strerror(errno));
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

static int resolve_targets_for_file(pid_t pid, const char *path, probe_target_t *targets, int max_targets)
{
    if (verbose) fprintf(stderr, "  [scan] > %s (map event)\n", path);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (verbose) fprintf(stderr, "  [scan] > skip (open failed: %s)\n", strerror(errno));
        return -1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        if (verbose) fprintf(stderr, "  [scan]   | skip (not a valid ELF)\n");
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
        if (verbose) fprintf(stderr, "  [scan]   | %s: %d symbols\n",
            shdr.sh_type == SHT_SYMTAB ? "SHT_SYMTAB" : "SHT_DYNSYM", num_symbols);

        for (int i = 0; i < num_symbols && count < max_targets; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);

            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0) continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') continue;
            if (!func_matches(name, func_re, func_re_count)) continue;

            if (verbose) fprintf(stderr, " [match] > %s!%s @ 0x%lx\n",
                path, name, (unsigned long)sym.st_value);

            if (!is_duplicate(probe_targets, probe_target_count + count, path, (unsigned long)sym.st_value)) {
                targets[count].pid = pid;
                strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1);
                targets[count].offset = (unsigned long)sym.st_value;
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
        if (!isdigit((unsigned char)ent->d_name[0])) 
            continue;

        pid_t pid = (pid_t)atoi(ent->d_name);

        char path[64], cmdline[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

        int fd = open(path, O_RDONLY);
        if (fd < 0) 
            continue;

        ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);

        if (n <= 0)
            continue;

        cmdline[n] = '\0';
        if (strcmp(cmdline, "zygote64") == 0 || strcmp(cmdline, "zygote") == 0) {
            result = pid;
            break;
        }
    }
    closedir(dir);
    return result;
}

static int seize_zygote(pid_t pid)
{
    if (ptrace(PTRACE_SEIZE, pid, NULL, (void *)(long)PTRACE_O_TRACEFORK) != 0) {
        fprintf(stderr, "[zygote] > ptrace SEIZE failed: %s\n", strerror(errno));
        return -1;
    }
    printf("[zygote] > seized PID %d\n", pid);
    return 0;
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
        
        if (verbose) fprintf(stderr, " [event]   | MMAP : %s\n", e->name);
        // Get full path from /proc/PID/maps based on start addreess
        char path[256];
        if (find_path_in_maps(header->pid, e->start, path, sizeof(path)) != 0)
            return 0;

        if (!mod_matches(path, mod_re, mod_has_slash, mod_re_count))
            return 0;

        if (list_libs) {
            printf("   [map] > %s\n", path);
            return 0;
        }

        // Resolve targets based on path
        int prev_count = probe_target_count;
        int max_targets = sizeof(probe_targets) / sizeof(probe_targets[0]) - prev_count;
        int resolved = resolve_targets_for_file(header->pid, path, probe_targets + prev_count, max_targets);

        if (resolved <= 0)
            return 0;

        probe_target_count += resolved;

        for (int i = prev_count; i < probe_target_count && !exiting; i++) {
            const char *bname = strrchr(probe_targets[i].mod_path, '/');
            bname = bname ? bname + 1 : probe_targets[i].mod_path;
            printf("[uprobe] > %s!%s @ 0x%lx\n",
                bname, probe_targets[i].func_name, probe_targets[i].offset);

            probe_links[i] = bpf_program__attach_uprobe(
                skel->progs.uprobe_open, false, -1,
                probe_targets[i].mod_path, probe_targets[i].offset);

            if (!probe_links[i])
                fprintf(stderr, "[uprobe] > FAILED: %s!%s\n", bname, probe_targets[i].func_name);
        }

        return 0;
    }

    if (header->type == ARES_EVENT_UNMAP) {
        const struct map_event *e = data;
        if (data_sz < sizeof(*e))
            return 0;

        if (verbose) fprintf(stderr, " [event]   | UNMAP: %s\n", e->name);

        if (list_libs) return 0;

        int removed = 0;
        for (int i = probe_target_count - 1; i >= 0; i--) {
            const char *bname = strrchr(probe_targets[i].mod_path, '/');
            bname = bname ? bname + 1 : probe_targets[i].mod_path;
            if (strcmp(bname, e->name) != 0)
                continue;

            if (probe_links[i])
                bpf_link__destroy(probe_links[i]);

            probe_targets[i] = probe_targets[probe_target_count - 1];
            probe_links[i]   = probe_links[probe_target_count - 1];
            probe_links[probe_target_count - 1] = NULL;
            probe_target_count--;
            removed++;
        }

        if (removed > 0)
            printf(" [unmap] > %s (%d probes removed)\n", e->name, removed);

        return 0;
    }

    if (header->type == ARES_EVENT_CALL) {
        if (list_libs) return 0;
        const struct event *e = data;

        if (data_sz < sizeof(*e)) return 0;

        probe_target_t *target = find_target_by_entry_addr(e->entry_addr, header->pid);
        if (target) {
            const char *bname = strrchr(target->mod_path, '/');
            bname = bname ? bname + 1 : target->mod_path;
            printf(" [event] > [CALL] %s PID:%d PPID:%d %s!%s @ 0x%lx\n",
                ts, e->h.pid, e->ppid, bname, target->func_name, target->offset);
        } else {
            printf(" [event] > [CALL] %s PID:%d PPID:%d %s!??? @ 0x%llx (unresolved)\n",
                ts, e->h.pid, e->ppid, e->comm, (unsigned long long)e->entry_addr);
            return 0;
        }

        if (e->caller_addr) {
            char caller_mod[128] = "";
            unsigned long caller_off = 0;
            if (lookup_caller(header->pid, e->caller_addr, caller_mod, sizeof(caller_mod), &caller_off) == 0)
                printf(" [event]   | caller: %s+0x%lx\n", caller_mod, caller_off);
            else
                printf(" [event]   | caller: 0x%llx\n", (unsigned long long)e->caller_addr);
        }

        for (__u32 i = 2; i < e->stack_depth; i++) {
            if (!e->call_stack[i]) break;
            char frame_mod[128] = "";
            unsigned long frame_off = 0;
            if (lookup_caller(header->pid, e->call_stack[i], frame_mod, sizeof(frame_mod), &frame_off) == 0)
                printf(" [event]   | #%u %s+0x%lx\n", i, frame_mod, frame_off);
            else
                printf(" [event]   | #%u 0x%llx\n", i, (unsigned long long)e->call_stack[i]);
        }

        for (int i = 0; i < NUM_ARGS; i++) {
            if (e->is_str[i]) {
                printf(" [event]   | args[%d] \"%s\"\n", i, e->strings[i]);
            } else {
                printf(" [event]   | args[%d] 0x%lx\n", i, e->args[i]);
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
    if (verbose) fprintf(stderr, "  [verb] > mode ON\n");
    if (list_libs) printf("  [info] > library detection mode\n");


    // Resolve application UID (if spawn mode)
    if (args.package_name[0] != '\0') {
        uid = resolve_uid(args.package_name);
        if (uid < 0) {
            fprintf(stderr, " [spawn] > could not resolve UID for '%s' (installed? run as root?)\n", args.package_name);
            err = -1;
            goto cleanup;
        }
        printf(" [spawn] > %s UID %d\n", args.package_name, uid);
    }


    // Prepare regex for pattern matching
    for (int i = 0; i < args.mod_pattern_count; i++) {
        mod_has_slash[i] = strchr(args.mod_patterns[i], '/') != NULL;
        if (regcomp(&mod_re[i], args.mod_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "   [err] > invalid regex pattern: %s\n", args.mod_patterns[i]);
            err = -1;
            goto cleanup;
        }
        mod_re_count++;
    }
    
    for (int i = 0; i < args.func_pattern_count; i++) {
        if (regcomp(&func_re[i], args.func_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "   [err] > invalid regex pattern: %s\n", args.func_patterns[i]);
            err = -1;
            goto cleanup;
        }
        func_re_count++;
    }


    // Open, load, attach BPF skeleton
    skel = ares_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "   [bpf] > failed to load skeleton\n");
        err = 1;
        goto cleanup;
    }

    bpf_program__set_autoattach(skel->progs.uprobe_open, false);
    err = ares_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "   [bpf] > failed to attach (uprobe_mmap in kallsyms?)\n");
        goto cleanup;
    }
    elf_version(EV_CURRENT);

    events_rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, NULL, NULL);
    if (!events_rb) {
        err = -1;
        fprintf(stderr, "    [rb] > failed to create ring buffer\n");
        goto cleanup;
    }


    // Find and resolve symbols in PID attach mode / spawn mode, then attach uprobes
    if (args.pid_count > 0) {
        if (!list_libs) {
            for (int i = 0; i < args.pid_count; i++) {
                printf(" [probe] > resolving targets for PID %d\n", args.pids[i]);
                int resolved = resolve_targets(
                    args.pids[i],
                    probe_targets + probe_target_count,
                    sizeof(probe_targets) / sizeof(probe_targets[0]) - probe_target_count
                );
                if (resolved > 0) probe_target_count += resolved;
            }

            if (probe_target_count == 0) {
                fprintf(stderr, " [probe] > no trace targets found\n");
                err = -1;
                goto cleanup;
            }
        }

        __u8 one = 1;
        for (int i = 0; i < args.pid_count; i++) {
            int pid_uid = get_pid_uid(args.pids[i]);
            if (pid_uid <= 0) {
                fprintf(stderr, " [probe] > could not resolve UID for PID %d\n", args.pids[i]);
                continue;
            }
            __u32 vuid = (__u32)pid_uid;
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
                fprintf(stderr, " [probe] > failed to set target UID %d: %s\n", pid_uid, strerror(errno));
                goto cleanup;
            }
            printf(" [probe] > PID %d UID %d\n", args.pids[i], pid_uid);
        }

        if (!list_libs) {
            for (int i = 0; i < probe_target_count && !exiting; i++) {
                const char *bname = strrchr(probe_targets[i].mod_path, '/');
                bname = bname ? bname + 1 : probe_targets[i].mod_path;
                printf("[uprobe] > %s!%s @ 0x%lx\n",
                    bname, probe_targets[i].func_name, probe_targets[i].offset);
                probe_links[i] = bpf_program__attach_uprobe(
                    skel->progs.uprobe_open,
                    false,
                    probe_targets[i].pid,
                    probe_targets[i].mod_path,
                    probe_targets[i].offset
                );
                if (!probe_links[i]) {
                    fprintf(stderr, "[uprobe] > FAILED: %s!%s\n", bname, probe_targets[i].func_name);
                    err = -1;
                    goto cleanup;
                }
            }
        }
    } else {
        char cmd[512], package_activity[256];

        // Find Zygote PID and seize for ptrace
        g_zygote_pid = find_zygote_pid();
        if (g_zygote_pid < 0) {
            fprintf(stderr, "[zygote] > failed to find Zygote PID\n");
            err = -1;
            goto cleanup;
        }
        if (seize_zygote(g_zygote_pid) != 0) {
            err = -1;
            goto cleanup;
        }

        // Force stop the package first
        snprintf(cmd, sizeof(cmd), "am force-stop %s", args.package_name);
        sh_exec(cmd, NULL, 0);

        // Make sure package is bye bye
        snprintf(cmd, sizeof(cmd), "pidof %s", args.package_name);
        for (int i = 0; i < 30; i++) {
            char pid_buf[32] = "";
            sh_exec(cmd, pid_buf, sizeof(pid_buf));
            if (pid_buf[0] == '\0') break;
            usleep(100000);
        }

        // Resolve main activity
        if (resolve_component(args.package_name, package_activity, sizeof(package_activity)) != 0) {
            fprintf(stderr, " [spawn] > failed to resolve component for %s\n", args.package_name);
            err = -1;
            goto cleanup;
        }

        // Update target UIDs for BPF program (filtering)
        __u8 one = 1;
        __u32 vuid = (__u32)uid;
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_uids), &vuid, &one, BPF_ANY) != 0) {
            fprintf(stderr, " [spawn] > failed to set target UID: %s\n", strerror(errno));
            goto cleanup;
        }

        // Start package
        snprintf(cmd, sizeof(cmd), "am start -S -n %s", package_activity);
        if (sh_exec(cmd, NULL, 0) != 0) {
            fprintf(stderr, " [spawn] > failed to start %s\n", args.package_name);
            err = -1;
            goto cleanup;
        }
    }
    
    // Zygote fork handling for pre-loaded libraries
    bool zygote_fork_done = (g_zygote_pid < 0);
    pid_t pending_children[64];
    int pending_children_count = 0;
    bool preload_scan_done = false;

    while (!exiting) {
        if (!zygote_fork_done) {
            int wstatus;
            pid_t wpid = waitpid(-1, &wstatus, WNOHANG | __WALL);

            if (wpid > 0) {
                int pending_idx = -1;
                for (int j = 0; j < pending_children_count; j++) {
                    if (pending_children[j] == wpid) { pending_idx = j; break; }
                }

                if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
                    if (pending_idx >= 0) {
                        if (WIFEXITED(wstatus))
                            fprintf(stderr, "[zygote] > child %d exited before scan (code %d)\n",
                                wpid, WEXITSTATUS(wstatus));
                        else
                            fprintf(stderr, "[zygote] > child %d killed before scan (sig %d)\n",
                                wpid, WTERMSIG(wstatus));
                        pending_children[pending_idx] = pending_children[--pending_children_count];
                    }

                } else if (WIFSTOPPED(wstatus)) {
                    int ptrace_event = wstatus >> 16;

                    if (wpid == g_zygote_pid && ptrace_event == PTRACE_EVENT_FORK) {
                        unsigned long child_pid_long = 0;
                        ptrace(PTRACE_GETEVENTMSG, g_zygote_pid, NULL, &child_pid_long);
                        pid_t new_child = (pid_t)child_pid_long;
                        printf("[zygote] > forked PID %d\n", new_child);
                        if (!preload_scan_done && pending_children_count < 64)
                            pending_children[pending_children_count++] = new_child;
                        ptrace(PTRACE_CONT, g_zygote_pid, NULL, NULL);

                    } else if (pending_idx >= 0) {
                        if (!preload_scan_done) {
                            if (!list_libs) {
                                if (verbose)
                                    fprintf(stderr, "[zygote] > child %d stopped - scanning\n", wpid);
                                printf("[zygote] > resolving pre-loaded libs for PID %d...\n", wpid);
                                int prev = probe_target_count;
                                int max = (int)(sizeof(probe_targets) / sizeof(probe_targets[0])) - prev;
                                int resolved = resolve_targets(wpid, probe_targets + prev, max);
                                printf("[zygote] > resolve_targets -> %d symbols\n", resolved);
                                if (resolved > 0) {
                                    probe_target_count += resolved;
                                    for (int i = prev; i < probe_target_count && !exiting; i++) {
                                        const char *bname = strrchr(probe_targets[i].mod_path, '/');
                                        bname = bname ? bname + 1 : probe_targets[i].mod_path;
                                        printf("[uprobe] > %s!%s @ 0x%lx\n",
                                            bname, probe_targets[i].func_name, probe_targets[i].offset);
                                        probe_links[i] = bpf_program__attach_uprobe(
                                            skel->progs.uprobe_open, false, -1,
                                            probe_targets[i].mod_path, probe_targets[i].offset);
                                        if (!probe_links[i])
                                            fprintf(stderr, "[uprobe] > FAILED: %s!%s\n",
                                                bname, probe_targets[i].func_name);
                                    }
                                    printf("[zygote] > attached %d uprobes for pre-loaded libs\n", resolved);
                                }
                            }
                            preload_scan_done = true;
                        }

                        if (verbose) fprintf(stderr, "[zygote]   | releasing child %d\n", wpid);
                        pending_children[pending_idx] = pending_children[--pending_children_count];
                        ptrace(PTRACE_DETACH, wpid, NULL, NULL);

                        if (pending_children_count == 0) {
                            if (ptrace(PTRACE_INTERRUPT, g_zygote_pid, NULL, NULL) == 0)
                                waitpid(g_zygote_pid, NULL, __WALL);
                            ptrace(PTRACE_DETACH, g_zygote_pid, NULL, NULL);
                            g_zygote_pid = -1;
                            zygote_fork_done = true;
                        }

                    } else {
                        ptrace(PTRACE_CONT, wpid, NULL, NULL);
                    }
                }
            }
        }

        err = ring_buffer__poll(events_rb, 50);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) { fprintf(stderr, "   [err] > ring buffer poll error: %d\n", err); break; }
    }


    // Cleanup mechanism
    cleanup:
        if (g_zygote_pid > 0) {
            if (ptrace(PTRACE_INTERRUPT, g_zygote_pid, NULL, NULL) == 0)
                waitpid(g_zygote_pid, NULL, __WALL);
            ptrace(PTRACE_DETACH, g_zygote_pid, NULL, NULL);
        }
        ring_buffer__free(events_rb);

        for (int i = 0; i < probe_target_count; i++) 
            if (probe_links[i]) bpf_link__destroy(probe_links[i]);
        for (int i = 0; i < mod_re_count; i++) regfree(&mod_re[i]);
        for (int i = 0; i < func_re_count; i++) regfree(&func_re[i]);

        ares_tracer_bpf__destroy(skel);

        return err < 0 ? -err : 0;
}