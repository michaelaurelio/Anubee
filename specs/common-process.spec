# Process/anti-tamper probes. Cross-engine (EPIC H): unprefixed/`funcs:`
# lines drive funcs/correlate; `syscall:`/`mod:` lines drive syscalls/mod
# from this same file via `-F`. Full grammar: docs/probe-specs.md.
libc.so!prctl(V,V,V,V,V)>V
libc.so!ptrace(V,V,V,V)>V

libc.so!kill(V,V)>V
libc.so!raise(V)>V
libc.so!abort()

syscall:ptrace
syscall:prctl
syscall:kill
syscall:tgkill
syscall:clone
syscall:clone3
syscall:execve
syscall:execveat

mod:proc-event
mod:execve
