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
#include <sys/resource.h>
#include <sys/types.h>
#include <bpf/libbpf.h>

#include "ares-tracer.h"
#include "ares-tracer.skel.h"


// Argument parser module using argp.h
const char *argp_program_version = "ares-tracer 1.0";
const char *argp_program_bug_address = "<vincentferdinand.k@gmail.com>";
static const char doc[] = "Android native function calls proof of concept using eBPF uprobes";
static const char args_doc[] = "";

static const struct argp_option options[] = {
    { "pid", 'p', "PID[,PID...]", 0, "Process ID(s) to inspect" },
    { "include-module", 'I', "MODULE", 0, "Target module to trace (path, name)" },
    { "include", 'i', "FUNCTION", 0, "Target function to trace (regex)" },
    { 0 }
};

struct args {
    pid_t pids[64];
    int pid_count;
    char mod_patterns[32][256];
    int mod_pattern_count;
    char func_patterns[32][256];
    int func_pattern_count;
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

        // No arguments case
        case ARGP_KEY_END:
            if (args->pid_count == 0)
                argp_usage(state);
            break;
        
        // Default case
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = { options, parse_opts, args_doc, doc };


// eBPF debug print
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // if (level == LIBBPF_DEBUG) return 0;
    // return vfprintf(stderr, format, args);
    return 0; // Suppress temporarily
}


// Ctrl + C handler
static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
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

static bool is_duplicate(probe_target_t *targets, int count, pid_t pid, const char *mod_path, unsigned long offset)
{
    for (int i = 0; i < count; i++) {
        if (targets[i].pid == pid && targets[i].offset == offset && strcmp(targets[i].mod_path, mod_path) == 0) {
            return true;
        }
    }
    return false;
}


// /proc/PID/maps parser module for target resolution
int mod_re_count = 0;
int func_re_count = 0;

static int resolve_targets(pid_t pid, probe_target_t *targets, int max_targets)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r"); 
    if (!f) {
        perror("fopen");
        return -1;
    }

    char line[512];
    int count = 0;

    // Read /proc/PID/maps line by line then parse
    while (fgets(line, sizeof(line), f) && count < max_targets) {
        char perms[5], path[256] = "";

        if (sscanf(line, "%*x-%*x %4s %*x %*s %*d %255s", perms, path) < 1) continue;
        if (path[0] != '/') continue;
        if (!strchr(perms, 'x')) continue; 
        if (!mod_matches(path, mod_re, mod_has_slash, mod_re_count)) continue;

        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;

        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf){
            close(fd);
            continue;
        }

        Elf_Scn *scn = NULL;

        // Basically iterate over ELF sections
        while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_targets) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr); // Get section header + section info

            // Only proceed if section is SHT_SYMTAB or SHT_DYNSYM (for symbols)
            if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
            if (shdr.sh_entsize == 0) continue;

            Elf_Data *data = elf_getdata(scn, NULL);
            int num_symbols = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < num_symbols && count < max_targets; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);

                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue; // Only get functions
                if (sym.st_value == 0) continue;                      // Skip undefined symbols
                
                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || name[0] == '\0') continue;
                if (!func_matches(name, func_re, func_re_count)) continue;

                if (!is_duplicate(targets, count, pid, path, (unsigned long)sym.st_value)) {
                    targets[count].pid = pid;
                    strncpy(targets[count].mod_path, path, sizeof(targets[count].mod_path) - 1);
                    strncpy(targets[count].func_name, name, sizeof(targets[count].func_name) - 1); 
                    targets[count].offset = (unsigned long)sym.st_value; // IMPORTANT: Basically the offset of function in the shared library
                    count++;
                }
            }
        }
        elf_end(elf);
        close(fd);
    }   

    fclose(f);
    return count;
}

probe_target_t probe_targets[4096];
int probe_target_count = 0;


// Handle events from ring buffer 
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
	char ts[32];
	time_t t;

    // Get current time
    time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // Print event information
    printf("%-8s %-32s %-7d %-7d %s\n", 
        ts, 
        e->comm, 
        e->pid, 
        e->ppid, 
        e->exit_event ? "EXIT" : "EXEC"
    );
    printf("     args:\n");
    for (int i = 0; i < NUM_ARGS; i++) {
        if (e->is_str[i]) {
            printf("        [%d] \"%s\"\n", i, e->strings[i]);
        } else {
            printf("        [%d] 0x%lx\n", i, e->args[i]);
        }
    }

    return 0;
}


// La driver function 
int main(int argc, char **argv)
{
    // Boilerplate setup
    struct ring_buffer *events_rb = NULL;
    struct ares_tracer_bpf *skel = NULL;
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    

    // Argument parsing
    struct args args = {
        .pid_count = 0,
    };
    argp_parse(&argp, argc, argv, 0, NULL, &args);


    // Prepare regex for pattern matching
    for (int i = 0; i < args.mod_pattern_count; i++) {
        mod_has_slash[i] = strchr(args.mod_patterns[i], '/') != NULL;
        if (regcomp(&mod_re[i], args.mod_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "Invalid regex pattern: %s\n", args.mod_patterns[i]);
            err = -1;
            goto cleanup;
        }
        mod_re_count++;
    }
    
    for (int i = 0; i < args.func_pattern_count; i++) {
        if (regcomp(&func_re[i], args.func_patterns[i], REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "Invalid regex pattern: %s\n", args.func_patterns[i]);
            err = -1;
            goto cleanup;
        }
        func_re_count++;
    }


    // Open and load BPF skeleton
    skel = ares_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }


    // Find and resolve symbols 
    elf_version(EV_CURRENT); 
    for (int i = 0; i < args.pid_count; i++) {
        printf("Resolving targets for PID %d\n", args.pids[i]);
        int resolved = resolve_targets(
            args.pids[i],
            probe_targets + probe_target_count,
            sizeof(probe_targets) / sizeof(probe_targets[0]) - probe_target_count
        );
        if (resolved > 0) probe_target_count += resolved;
    }

    if (probe_target_count == 0) {
        fprintf(stderr, "No trace targets found\n");
        err = -1;
        goto cleanup;
    }

    for (int i = 0; i < probe_target_count; i++) {
        printf("Attaching uprobe to %s in %s at offset 0x%lx\n", 
            probe_targets[i].func_name, 
            probe_targets[i].mod_path, 
            probe_targets[i].offset
        );
        skel->links.uprobe_open = bpf_program__attach_uprobe(
            skel->progs.uprobe_open, 
            false, 
            probe_targets[i].pid, 
            probe_targets[i].mod_path, 
            probe_targets[i].offset
        );

        if (!skel->links.uprobe_open) {
            fprintf(stderr, "Failed to attach uprobe to %s in %s\n", probe_targets[i].func_name, probe_targets[i].mod_path);
            err = -1;
            goto cleanup;
        }
    }
    

    // Set up ring buffer polling
    events_rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, NULL, NULL);
    if (!events_rb) {
        err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
    }

    printf("%-8s %-32s %-7s %-7s %s\n", "TIME", "COMM", "PID", "PPID", "?");
    while (!exiting) {
        err = ring_buffer__poll(events_rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }


    // Cleanup
    cleanup:
        ring_buffer__free(events_rb);
        ares_tracer_bpf__destroy(skel);

        for (int i = 0; i < mod_re_count; i++) regfree(&mod_re[i]);
        for (int i = 0; i < func_re_count; i++) regfree(&func_re[i]);

        return err < 0 ? -err : 0;
}