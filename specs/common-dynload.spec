# Dynamic-load probes. Cross-engine (EPIC H): unprefixed/`funcs:` lines
# drive funcs/correlate; `syscall:`/`mod:` lines drive syscalls/mod from
# this same file via `-F`. Full grammar: docs/probe-specs.md.
libdl.so!dlopen(S,V)>V
libdl.so!android_dlopen_ext(S,V,V)>V
libdl.so!dlsym(V,S)>V

syscall:mmap
syscall:mprotect
syscall:memfd_create

mod:fileless-detect
