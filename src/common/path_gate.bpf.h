// SPDX-License-Identifier: GPL-2.0
// Shared bounded path-prefix check for BPF programs that gate on filesystem
// paths (mod file-access, mod ransomware-burst). Source-shared only -- each
// BPF object that #includes this gets its own compiled copy, so this has no
// effect on the detectability firewall (that's about attached programs, not
// shared code); see CLAUDE.md's "Shared BPF is source-shared" rule.
#ifndef __ARES_PATH_GATE_BPF_H
#define __ARES_PATH_GATE_BPF_H

// Bounded prefix compare: path is a fixed-size local/ringbuf buffer (always
// >= 32 bytes), so indexing up to 31 is always safe regardless of prefix
// length; `plen` only controls how much of that fixed window we compare.
static __always_inline int path_has_prefix(const char *path, const char *prefix, int plen)
{
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= plen)
            break;
        if (path[i] != prefix[i])
            return 0;
    }
    return 1;
}

#endif /* __ARES_PATH_GATE_BPF_H */
