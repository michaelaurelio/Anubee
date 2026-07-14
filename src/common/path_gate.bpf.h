// SPDX-License-Identifier: GPL-2.0
// Shared bounded path-prefix check for BPF programs that gate on filesystem
// paths (mod file-access, mod massdelete-detect). Source-shared only -- each
// BPF object that #includes this gets its own compiled copy, so this has no
// effect on the detectability firewall (that's about attached programs, not
// shared code).
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

// Bounded substring search: does `path` contain `needle` (length `nlen`,
// max 16) anywhere within its first 48 bytes? Double loop, both bounds
// fixed/unrolled -- same verifier-provable shape as the FNV hash loop in
// massdelete_detect.bpf.c. path is always a fixed 256-byte buffer
// (FILE_PATH_LEN), so indexing up to 48+16=64 is always safe. The 48-byte
// window is a deliberate bound (mirrors path_hash's own 64-byte bound) --
// a needle only appearing later in an unusually long path is a documented,
// accepted miss, not a correctness bug (see mod exfil-burst design doc).
static __always_inline int path_has_component(const char *path, const char *needle, int nlen)
{
    #pragma unroll
    for (int start = 0; start < 48; start++) {
        int match = 1;
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            if (i >= nlen)
                break;
            if (path[start + i] != needle[i]) { match = 0; break; }
        }
        if (match)
            return 1;
    }
    return 0;
}

#endif /* __ARES_PATH_GATE_BPF_H */
