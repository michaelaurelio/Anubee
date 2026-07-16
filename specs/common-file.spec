# File-access probes. Cross-engine post-SPEC1: an unprefixed/`funcs:` line
# drives funcs/correlate (uprobe); `syscall:`/`lib:`/`mod:` lines (like the
# syscall:openat below) drive syscalls/dump/mod from this same file via `-F`.
# Full grammar: DOCUMENTATION.md §3.
libc.so!fopen(S,S)>V
libc.so!fgets(S,V,V)>V
libc.so!open(S,V,V)>V
libc.so!openat(F,S,V,V)>V
libc.so!read(F,S,V)>V
libc.so!readlink(S,S,V)>V
libc.so!opendir(S)>V

libc.so!stat(S,V)>V
libc.so!lstat(S,V)>V
libc.so!access(S,V)>V

libc.so!inotify_add_watch(V,S,V)>V

syscall:openat
syscall:openat2
syscall:read
syscall:readlinkat
syscall:newfstatat
syscall:faccessat
syscall:statx
syscall:unlinkat

mod:file-access
