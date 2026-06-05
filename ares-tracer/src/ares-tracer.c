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
    { 0 }
};

struct args {
    pid_t pids[64];
    int pid_count;
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
    return vfprintf(stderr, format, args);
}


// Ctrl + C handler
static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}


// /proc/PID/maps parser module for symbol resolution
typedef struct {
    unsigned long base;
    char path[256];
} module_t;

static int parse_maps(pid_t pid, module_t *modules, int max_modules)
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
    while (fgets(line, sizeof(line), f) && count < max_modules) {
        unsigned long start, end;
        char perms[5], path[256] = "";

        if (sscanf(line, "%lx-%lx %4s %*x %*s %*d %255s", &start, &end, perms, path) < 3)
            continue;

        if (path[0] != '/') continue;
        if (!strchr(perms, 'x')) continue; 

        modules[count].base = start;
        strncpy(modules[count].path, path, sizeof(modules[count].path) - 1);
        count++;
    }

    fclose(f);
    return count;
}

typedef struct {
    char name[256];
    unsigned long st_value; // ELF vaddr (offset for .so)
} symbol_t;

static int parse_symbols(const char *path, symbol_t *symbols, int max_symbols)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    elf_version(EV_CURRENT); 
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf){
        close(fd);
        return 0;
    }

    int count = 0;
    Elf_Scn *scn = NULL;

    // Basically iterate over ELF sections
    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_symbols) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr); // Get section header + section info

        // Only proceed if section is SHT_SYMTAB or SHT_DYNSYM (for symbols)
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        if (shdr.sh_entsize == 0) continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        int num_symbols = shdr.sh_size / shdr.sh_entsize;

        for (int i = 0; i < num_symbols && count < max_symbols; i++) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);

            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue; // Only get functions
            if (sym.st_value == 0) continue;                      // Skip undefined symbols

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') continue;

            strncpy(symbols[count].name, name, sizeof(symbols[count].name) - 1); 
            symbols[count].st_value = (unsigned long)sym.st_value; // IMPORTANT: Basically the offset of function in the shared library
            count++;
        }
    }

    elf_end(elf);
    close(fd);
    return count;
}

module_t modules[512];
symbol_t symbols[4096];


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


// TEMP VALUES PLS REMOVE nanti
// #define TARGET_LIB "/apex/com.android.runtime/lib64/bionic/libc.so"
#define TARGET_LIB "libc.so"
#define TARGET_FUNC "open"


// La driver function 
int main(int argc, char **argv)
{
    // Boilerplate setup
    struct ring_buffer *events_rb = NULL;
    struct ares_tracer_bpf *skel;
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    // Argument parsing
    struct args args = {
        .pid_count = 0,
    };
    argp_parse(&argp, argc, argv, 0, NULL, &args);


    // Open and load BPF skeleton
    skel = ares_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }


    // Find and resolve symbols 
    for (int i = 0; i < args.pid_count; i++) {
        printf("Resolving symbols for PID %d...\n", args.pids[i]);
        int number_modules = parse_maps(args.pids[i], modules, 512);
        for (int j = 0; j < number_modules; j++) {
            if (strstr(modules[j].path, TARGET_LIB) == NULL)
                continue;   // TEMP: Only resolve libc.so / TARGET_LIB
            
            int number_symbols = parse_symbols(modules[j].path, symbols, 4096);
            for (int k = 0; k < number_symbols; k++) {
                if (strcmp(symbols[k].name, TARGET_FUNC) == 0) {
                    printf("[+] Found %s at offset 0x%lx in %s\n", TARGET_FUNC, symbols[k].st_value, modules[j].path);
                    skel->links.uprobe_open = bpf_program__attach_uprobe(
                        skel->progs.uprobe_open,
                        false, // uprobe, set true for uretprobe 
                        args.pids[i],
                        modules[j].path,
                        symbols[k].st_value
                    );

                    if (!skel->links.uprobe_open) {
                        err = -errno;
                        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
                        goto cleanup;
                    }
                }
            }
        }
    }


    // Attaches BPF skeleton (if later add auto-attach)
    // err = uprobe_bpf__attach(skel);
    // if (err) {
    //     fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
    //     goto cleanup;
    // }
    

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
        return err < 0 ? -err : 0;
}