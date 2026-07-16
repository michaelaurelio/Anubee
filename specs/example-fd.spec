# Teaching example for the F (fd) argtype, decoded to its resolved path.
# funcs:-only. Also used as a test fixture (tests/test_probe_spec.c).
libc.so!openat(F,S,V,V)>V
libc.so!read(F,S,V)>V
libc.so!write(F,S,V)>V
