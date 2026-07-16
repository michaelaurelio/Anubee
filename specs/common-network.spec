# Network probes. Cross-engine (EPIC H): unprefixed/`funcs:` lines drive
# funcs/correlate; `syscall:`/`mod:` lines drive syscalls/mod from this same
# file via `-F`. Full grammar: docs/probe-specs.md.
libc.so!socket(V,V,V)>V
libc.so!connect(V,A,V)>V

syscall:connect
syscall:sendto
syscall:bind
syscall:recvfrom

mod:exfil-detect
