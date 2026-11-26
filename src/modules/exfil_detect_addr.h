// SPDX-License-Identifier: GPL-2.0
// exfil-detect's "does this destination count as outbound" rule. Pure and
// header-only so the BPF program (exfil_detect.bpf.c) and the host test
// (tests/test_exfil_detect_addr.c) compile the same code. No libc/vmlinux
// types: plain unsigned char/short only.
//
// Only a non-loopback, non-unspecified IPv4/IPv6 peer counts. Everything else
// -- AF_UNIX (logd's logdw socket gets every Log.* line, plus dnsproxyd and
// fwmarkd), AF_NETLINK, ... -- is local IPC, and counting it turned an app's
// own logging into a false exfil alert.
#ifndef __ANUBEE_EXFIL_DETECT_ADDR_H
#define __ANUBEE_EXFIL_DETECT_ADDR_H

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define EXFIL_AF_INET  2   // Linux AF_INET  (no <sys/socket.h> in a BPF unit)
#define EXFIL_AF_INET6 10  // Linux AF_INET6

// addr: the peer address in network byte order -- 4 bytes for AF_INET, 16 for
// AF_INET6; not read for any other family.
static __always_inline int exfil_addr_is_outbound(unsigned short family,
                                                  const unsigned char *addr)
{
    if (family == EXFIL_AF_INET)
        return addr[0] != 127 &&
               (addr[0] | addr[1] | addr[2] | addr[3]) != 0;
    if (family == EXFIL_AF_INET6) {
        unsigned char hi = 0;   // OR of bytes 0..9 (zero for ::/96 and ::ffff:0:0/96)
        for (int i = 0; i < 10; i++)
            hi |= addr[i];
        if (hi == 0 && addr[10] == 0xff && addr[11] == 0xff)   // v4-mapped
            return addr[12] != 127 &&
                   (addr[12] | addr[13] | addr[14] | addr[15]) != 0;
        if (hi == 0 && (addr[10] | addr[11] | addr[12] | addr[13] | addr[14]) == 0)
            return addr[15] > 1;   // :: (unspecified) and ::1 (loopback) are local
        return 1;
    }
    return 0;
}

// sa: raw sockaddr bytes as copied from user memory (>= 24 bytes readable).
// sa_family is host byte order at offset 0; sin_addr at 4, sin6_addr at 8.
static __always_inline int exfil_sockaddr_is_outbound(const unsigned char *sa)
{
    unsigned short fam = (unsigned short)(sa[0] | (sa[1] << 8));   // little-endian (arm64)
    if (fam == EXFIL_AF_INET)
        return exfil_addr_is_outbound(fam, sa + 4);
    if (fam == EXFIL_AF_INET6)
        return exfil_addr_is_outbound(fam, sa + 8);
    return 0;
}

#endif /* __ANUBEE_EXFIL_DETECT_ADDR_H */
