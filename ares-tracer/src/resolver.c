#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <argp.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>


// Argument parser module using argp.h
const char *argp_program_version = "resolver 1.0";
const char *argp_program_bug_address = "<vincentferdinand.k@gmail.com>";
static const char doc[] = "Symbols resolver proof of concept";
static const char args_doc[] = "";

static const struct argp_option options[] = {
    { "pid", 'p', "PID[,PID...]", 0, "Process ID(s) to inspect" },
    { 0 }
};

struct args {
    pid_t pids[64];
    int pid_count;
    bool verbose;
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
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

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


// Main function
int main(int argc, char **argv)
{
    struct args args = {
        .pid_count = 0,
        .verbose = false
    };
    argp_parse(&argp, argc, argv, 0, NULL, &args);

    for (int i = 0; i < args.pid_count; i++) {
        printf("PID: %d\n", args.pids[i]);

        int number_modules = parse_maps(args.pids[i], modules, 512);
        for (int j = 0; j < number_modules; j++) {
            int number_symbols = parse_symbols(modules[j].path, symbols, 4096);
            printf("%s  (base=0x%lx)\n", modules[j].path, modules[j].base);
            for (int k = 0; k < number_symbols; k++) {
                printf("  0x%lx %s\n", symbols[k].st_value, symbols[k].name);
            }
        }
    }

    return 0;
}