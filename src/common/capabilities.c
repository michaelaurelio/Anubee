// SPDX-License-Identifier: GPL-2.0
// Firewall-aware capability registry — see capabilities.h.
#include "common/capabilities.h"

#include <string.h>

// The single source of firewall truth. Only the uprobe-bearing capabilities
// (funcs' entry BRK; correlate's entry uprobe, plus its --returns trampoline
// when added) write into the target. syscalls (kprobe), lib (mmap-kprobe) and
// dump (/proc/<pid>/mem reads) write nothing into the target. `trace` runs the
// funcs uprobe alongside the syscalls kprobe, so it is loud by construction.
static const struct ares_bpf_object g_objects[] = {
    { "syscalls",  false },
    { "funcs",     true  },
    { "lib",       false },
    { "dump",      false },
    { "correlate", true  },
    { "trace",     true  },
    // Analyzers (src/modules/) — each owns its own BPF object.
    { "mod:proc-event", false },  // tracepoints only; zero uprobes
    { "mod:execve",     false },  // kprobes/tracepoint; zero uprobes
    { "mod:prop-read",  true  },  // uprobes on libc; writes target memory
    { "mod:file-access", false }, // kprobes on openat/openat2; zero uprobes
    { "mod:ransomware-burst", false }, // kprobes on renameat/renameat2/unlinkat; zero uprobes
    { "mod:exfil-burst", false }, // kprobes on openat/openat2/connect/sendto/write/writev/close; zero uprobes
    { "mod:a11y-abuse", false }, // tracepoint on binder_transaction; zero uprobes
    { "mod:fileless-exec", false }, // kprobes on do_mmap/__arm64_sys_prctl; zero uprobes
    { "mod:mediaproj-abuse", false }, // tracepoint on binder_transaction (context only) + dumpsys poll; zero uprobes
};

const struct ares_bpf_object *ares_bpf_objects(int *count)
{
    if (count)
        *count = (int)(sizeof(g_objects) / sizeof(g_objects[0]));
    return g_objects;
}

bool ares_object_writes_target(const char *name)
{
    // AA2 fix: fail closed. No name, or a name not in the table, means we don't
    // know this capability is quiet — assume loud until it's registered, rather
    // than silently telling the operator "stealthy" for something unaudited.
    if (!name)
        return true;
    for (size_t i = 0; i < sizeof(g_objects) / sizeof(g_objects[0]); i++)
        if (strcmp(g_objects[i].name, name) == 0)
            return g_objects[i].writes_target_memory;
    return true;
}

bool ares_quiet_config_ok(const char *const *loaded, int n)
{
    for (int i = 0; i < n; i++)
        if (ares_object_writes_target(loaded[i]))
            return false;
    return true;
}
