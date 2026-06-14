# banksaqu-rasp.spec
# Uprobe spec for Bank BJB Digital RASP mechanism analysis.
# Targets the 5 mechanism categories identified in the proc-events trace.
#
# Usage:
#   ./ares-tracer -P bjj.bank.digital.indo.prod -F banksaqu-rasp.spec -x -o banksaqu.csv
#
# The -x flag runs alongside this file to keep process spawn/exit context.
# All probes attach to libc.so and fire for the main app (26030) AND any
# UID-matching subprocess (e.g. the guardian 26212) automatically.


# ── 1. SHELL COMMAND EXECUTION ────────────────────────────────────────────────
# Reveals the exact binary path for every pm/getprop/ps/cat/mount/which call.
# args[0] = binary path (S)
# args[1] = argv[] pointer (V) — raw pointer; path is the actionable field
# args[2] = envp[] pointer (V)
# RET fires only on failure (execve does not return on success).
libc.so!execve(S,V,V)>V

# posix_spawn: NDK-level alternative to fork+execve used by some native code.
# args[0] = pid_t* output pointer (V)
# args[1] = binary path (S)
# args[2..5] = file actions / attrs / argv / envp (V)
libc.so!posix_spawn(V,S,V,V,V,V)>V


# ── 2. SYSTEM PROPERTY READS ──────────────────────────────────────────────────
# Reveals every property the RASP reads: ro.debuggable, ro.secure,
# ro.build.tags, ro.build.fingerprint, etc.
# args[0] = property name (S) — printed at CALL
# args[1] = value output buffer (S) — re-read at RET once filled
# RET: strings[1] contains the actual property value
libc.so!__system_property_get(S,S)>V


# ── 3. FILE PROBING ───────────────────────────────────────────────────────────
# openat: primary file-open wrapper in bionic.
# args[0] = dirfd (V, typically AT_FDCWD = -100)
# args[1] = path (S) — the target file
# args[2] = flags (V, O_RDONLY=0, O_RDWR=2, etc.)
# RET = fd (>=0 success, -1 failure) — cat/which exit 1 means open failed here
libc.so!openat(V,S,V)>V

# access: file existence check without opening; used for /system/xbin/su etc.
# args[0] = path (S)
# args[1] = mode flags (V, F_OK=0 existence only, R_OK=4, X_OK=1)
# RET = 0 (exists/permitted), -1 (ENOENT / EACCES)
libc.so!access(S,V)>V

# faccessat: modern dirfd form of access.
# args[0] = dirfd (V)
# args[1] = path (S)
# args[2] = mode (V)
# args[3] = flags (V, AT_SYMLINK_NOFOLLOW etc.)
libc.so!faccessat(V,S,V,V)>V

# readlink: used to resolve /proc/self/exe, /proc/self/cmdline,
# and to detect /proc/pid/exe pointing outside expected paths.
# args[0] = path to dereference (S)
# args[1] = output buffer (S) — re-read at RET with resolved path
# args[2] = bufsize (V)
libc.so!readlink(S,S,V)>V


# ── 4. SIGNAL DELIVERY ────────────────────────────────────────────────────────
# kill: captures SIGKILL (9) to the double-fork intermediate and
# SIGTERM (15) to timed-out getprop/ps child processes.
# args[0] = target pid (V)
# args[1] = signal number (V) — 9=SIGKILL, 15=SIGTERM
libc.so!kill(V,V)>V

# tgkill: thread-targeted signal; used when killing a specific thread TID.
# args[0] = tgid (V)
# args[1] = tid (V)
# args[2] = signal (V)
libc.so!tgkill(V,V,V)>V


# ── 5. PROCESS FORKING ────────────────────────────────────────────────────────
# fork: captures the double-fork initiation with a full call stack into
# the RASP class that triggers it (Thread-23 in the observed trace).
# Empty () = emit CALL event (for stack trace) + RET (child PID in parent / 0 in child).
libc.so!fork()>V


# ── 6. THREAD NAMING ──────────────────────────────────────────────────────────
# Captures full thread names before the 15-char kernel comm truncation.
# Reveals the complete RASP SDK thread names (e.g. "AppGuard re-initialized...").
# args[0] = pthread_t handle (V)
# args[1] = name string (S)
libc.so!pthread_setname_np(V,S)>V

# prctl: catches PR_SET_NAME (15) thread renames and PR_SET_PDEATHSIG (1)
# parent-death signal setup used in guardian subprocess patterns.
# args[0] = option (V) — interpret 1=PDEATHSIG, 4=DUMPABLE, 15=SET_NAME
# args[1] = typed S to capture the name string when option=PR_SET_NAME;
#           prints as (?str) for non-pointer options — acceptable noise.
# args[2..4] = remaining option args (V)
libc.so!prctl(V,S,V,V,V)>V
