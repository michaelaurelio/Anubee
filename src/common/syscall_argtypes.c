// SPDX-License-Identifier: GPL-2.0
#include "common/syscall_argtypes.h"

#include <bpf/bpf.h>
#include <linux/types.h>
#include <sys/syscall.h>

#define A0 (1u << 0)
#define A1 (1u << 1)
#define A2 (1u << 2)
#define A3 (1u << 3)
#define A4 (1u << 4)

// Which of args[0..3] are a const char* (path/string), per syscall. Not
// exported - only install_arg_types() below needs it, on both engines.
static const struct anubee_arg_mask_entry g_str_args[] = {
#ifdef __NR_openat
    { __NR_openat, A1 },
#endif
#ifdef __NR_openat2
    { __NR_openat2, A1 },
#endif
#ifdef __NR_name_to_handle_at
    { __NR_name_to_handle_at, A1 },
#endif
#ifdef __NR_readlinkat
    { __NR_readlinkat, A1 },
#endif
#ifdef __NR_newfstatat
    { __NR_newfstatat, A1 },
#endif
#ifdef __NR_statx
    { __NR_statx, A1 },
#endif
#ifdef __NR_faccessat
    { __NR_faccessat, A1 },
#endif
#ifdef __NR_faccessat2
    { __NR_faccessat2, A1 },
#endif
#ifdef __NR_fchmodat
    { __NR_fchmodat, A1 },
#endif
#ifdef __NR_fchownat
    { __NR_fchownat, A1 },
#endif
#ifdef __NR_unlinkat
    { __NR_unlinkat, A1 },
#endif
#ifdef __NR_mkdirat
    { __NR_mkdirat, A1 },
#endif
#ifdef __NR_mknodat
    { __NR_mknodat, A1 },
#endif
#ifdef __NR_utimensat
    { __NR_utimensat, A1 },
#endif
#ifdef __NR_renameat
    { __NR_renameat, A1 | A3 },
#endif
#ifdef __NR_renameat2
    { __NR_renameat2, A1 | A3 },
#endif
#ifdef __NR_linkat
    { __NR_linkat, A1 | A3 },
#endif
#ifdef __NR_symlinkat
    { __NR_symlinkat, A0 | A2 },
#endif
#ifdef __NR_execve
    { __NR_execve, A0 },
#endif
#ifdef __NR_execveat
    { __NR_execveat, A1 },
#endif
#ifdef __NR_chdir
    { __NR_chdir, A0 },
#endif
#ifdef __NR_chroot
    { __NR_chroot, A0 },
#endif
#ifdef __NR_truncate
    { __NR_truncate, A0 },
#endif
#ifdef __NR_statfs
    { __NR_statfs, A0 },
#endif
#ifdef __NR_getxattr
    { __NR_getxattr, A0 | A1 },
#endif
#ifdef __NR_lgetxattr
    { __NR_lgetxattr, A0 | A1 },
#endif
#ifdef __NR_setxattr
    { __NR_setxattr, A0 | A1 },
#endif
#ifdef __NR_mount
    { __NR_mount, A0 | A1 | A2 },
#endif
#ifdef __NR_umount2
    { __NR_umount2, A0 },
#endif
#ifdef __NR_pivot_root
    { __NR_pivot_root, A0 | A1 },
#endif
};

void install_arg_types(int fd)
{
    for (size_t i = 0; i < sizeof(g_str_args) / sizeof(g_str_args[0]); i++) {
        __u32 k = (__u32)g_str_args[i].nr;
        __u8 v = g_str_args[i].mask;
        if (k < 512)
            bpf_map_update_elem(fd, &k, &v, BPF_ANY);
    }
}

// Which arg holds a sockaddr* (the addrlen is the next arg); connect/bind at
// arg1, sendto at arg4.
const struct anubee_arg_sock_entry g_sock_args[] = {
#ifdef __NR_connect
    { __NR_connect, 1 },
#endif
#ifdef __NR_bind
    { __NR_bind, 1 },
#endif
#ifdef __NR_sendto
    { __NR_sendto, 4 },
#endif
};
const size_t g_sock_args_count = sizeof(g_sock_args) / sizeof(g_sock_args[0]);

void install_sock_args(int fd)
{
    for (size_t i = 0; i < sizeof(g_sock_args) / sizeof(g_sock_args[0]); i++) {
        __u32 k = (__u32)g_sock_args[i].nr;
        __u8 v = (__u8)(g_sock_args[i].arg + 1);
        if (k < 512)
            bpf_map_update_elem(fd, &k, &v, BPF_ANY);
    }
}

int arg_sock_index(unsigned long long nr)
{
    for (size_t i = 0; i < sizeof(g_sock_args) / sizeof(g_sock_args[0]); i++)
        if ((unsigned long long)g_sock_args[i].nr == nr)
            return g_sock_args[i].arg;
    return -1;
}

const struct anubee_arg_mask_entry g_fd_args[] = {
#ifdef __NR_read
    { __NR_read, A0 },
#endif
#ifdef __NR_write
    { __NR_write, A0 },
#endif
#ifdef __NR_pread64
    { __NR_pread64, A0 },
#endif
#ifdef __NR_pwrite64
    { __NR_pwrite64, A0 },
#endif
#ifdef __NR_readv
    { __NR_readv, A0 },
#endif
#ifdef __NR_writev
    { __NR_writev, A0 },
#endif
#ifdef __NR_close
    { __NR_close, A0 },
#endif
#ifdef __NR_fstat
    { __NR_fstat, A0 },
#endif
#ifdef __NR_fstatfs
    { __NR_fstatfs, A0 },
#endif
#ifdef __NR_lseek
    { __NR_lseek, A0 },
#endif
#ifdef __NR_fsync
    { __NR_fsync, A0 },
#endif
#ifdef __NR_fdatasync
    { __NR_fdatasync, A0 },
#endif
#ifdef __NR_ftruncate
    { __NR_ftruncate, A0 },
#endif
#ifdef __NR_fcntl
    { __NR_fcntl, A0 },
#endif
#ifdef __NR_ioctl
    { __NR_ioctl, A0 },
#endif
#ifdef __NR_getdents64
    { __NR_getdents64, A0 },
#endif
#ifdef __NR_flock
    { __NR_flock, A0 },
#endif
#ifdef __NR_fchdir
    { __NR_fchdir, A0 },
#endif
#ifdef __NR_fchmod
    { __NR_fchmod, A0 },
#endif
#ifdef __NR_fchown
    { __NR_fchown, A0 },
#endif
#ifdef __NR_dup
    { __NR_dup, A0 },
#endif
#ifdef __NR_dup3
    { __NR_dup3, A0 },
#endif
#ifdef __NR_sendto
    { __NR_sendto, A0 },
#endif
#ifdef __NR_recvfrom
    { __NR_recvfrom, A0 },
#endif
#ifdef __NR_sendmsg
    { __NR_sendmsg, A0 },
#endif
#ifdef __NR_recvmsg
    { __NR_recvmsg, A0 },
#endif
#ifdef __NR_connect
    { __NR_connect, A0 },
#endif
#ifdef __NR_getsockopt
    { __NR_getsockopt, A0 },
#endif
#ifdef __NR_setsockopt
    { __NR_setsockopt, A0 },
#endif
#ifdef __NR_epoll_ctl
    { __NR_epoll_ctl, A0 | A4 },
#endif
#ifdef __NR_mmap
    { __NR_mmap, A4 },
#endif
    // *at family: arg0 is the dirfd.
#ifdef __NR_openat
    { __NR_openat, A0 },
#endif
#ifdef __NR_openat2
    { __NR_openat2, A0 },
#endif
#ifdef __NR_newfstatat
    { __NR_newfstatat, A0 },
#endif
#ifdef __NR_readlinkat
    { __NR_readlinkat, A0 },
#endif
#ifdef __NR_faccessat
    { __NR_faccessat, A0 },
#endif
#ifdef __NR_faccessat2
    { __NR_faccessat2, A0 },
#endif
#ifdef __NR_fchmodat
    { __NR_fchmodat, A0 },
#endif
#ifdef __NR_fchownat
    { __NR_fchownat, A0 },
#endif
#ifdef __NR_unlinkat
    { __NR_unlinkat, A0 },
#endif
#ifdef __NR_mkdirat
    { __NR_mkdirat, A0 },
#endif
#ifdef __NR_utimensat
    { __NR_utimensat, A0 },
#endif
#ifdef __NR_statx
    { __NR_statx, A0 },
#endif
#ifdef __NR_name_to_handle_at
    { __NR_name_to_handle_at, A0 },
#endif
#ifdef __NR_execveat
    { __NR_execveat, A0 },
#endif
};
const size_t g_fd_args_count = sizeof(g_fd_args) / sizeof(g_fd_args[0]);

unsigned arg_fd_mask(unsigned long long nr)
{
    for (size_t i = 0; i < sizeof(g_fd_args) / sizeof(g_fd_args[0]); i++)
        if ((unsigned long long)g_fd_args[i].nr == nr)
            return g_fd_args[i].mask;
    return 0;
}

// Per-syscall argument count (arm64 ABI) - see syscall_argtypes.h. Moved here
// (byte-identical) from src/syscalls/syscalls.c's own g_argc[]/g_nargc.
const struct anubee_arg_count_entry g_arg_counts[] = {
#include "common/syscall_argc.h"
};
const size_t g_arg_counts_count = sizeof(g_arg_counts) / sizeof(g_arg_counts[0]);

int arg_count(unsigned long long nr)
{
    for (size_t i = 0; i < g_arg_counts_count; i++)
        if ((unsigned long long)g_arg_counts[i].nr == nr)
            return g_arg_counts[i].count;
    return 6; // unknown syscall: show all 6 arm64 arg registers (x0..x5)
}
