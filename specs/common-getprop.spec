# System-property-read probes. Cross-engine (EPIC H): unprefixed/`funcs:`
# lines drive funcs/correlate; the `mod:` line drives mod from this same
# file via `-F`. No syscall: peer here — property reads go through
# __system_property_* / a property-service socket, not a distinct syscall.
# Full grammar: docs/probe-specs.md.
libc.so!__system_property_get(S,S)>V
libc.so!__system_property_find(S)>V
libc.so!__system_property_foreach(V,V)>V

mod:prop-read
