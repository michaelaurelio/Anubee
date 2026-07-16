# String-scan probes. funcs:-only (default kind, no prefix needed): plain
# libc calls with no syscall or mod-analyzer peer. Read by funcs/correlate;
# other engines have nothing to match here. Full grammar: docs/probe-specs.md.
libc.so!strstr(S,S)>S
libc.so!strcmp(S,S)>V
libc.so!strncmp(S,S,V)>V
libc.so!strchr(S,V)>V
libc.so!strtol(S,V,V)>V
libc.so!snprintf(S,V,S)>V

libc.so!regcomp(V,S,V)>V

libc.so!getenv(S)>S
