#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <argp.h>
#include <sys/types.h>

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
        case 'p':
            char *tok = strtok(arg, ",");
            while (tok && args->pid_count < 64) {
                args->pids[args->pid_count++] = (pid_t)atoi(tok); 
                tok = strtok(NULL, ",");
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

int main(int argc, char **argv)
{
    struct args args = {
        .pid_count = 0,
        .verbose = false
    };
    argp_parse(&argp, argc, argv, 0, NULL, &args);

    for (int i = 0; i < args.pid_count; i++) {
        printf("PID: %d\n", args.pids[i]);
    }

    return 0;
}