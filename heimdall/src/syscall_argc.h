/* syscall_argc.h
 *
 * Per-syscall argument counts for the arm64 (asm-generic) ABI, so the printer
 * shows only the real arguments instead of leftover register garbage. Values
 * are the SYSCALL_DEFINEn arities. Entries are #ifdef-guarded so the table
 * builds against any sysroot; unknown syscalls fall back to printing all 6.
 *
 * Included once to initialize a { nr, count } array.
 */
#ifdef __NR_io_setup
	{ __NR_io_setup, 2 },
#endif
#ifdef __NR_io_destroy
	{ __NR_io_destroy, 1 },
#endif
#ifdef __NR_io_submit
	{ __NR_io_submit, 3 },
#endif
#ifdef __NR_io_cancel
	{ __NR_io_cancel, 3 },
#endif
#ifdef __NR_io_getevents
	{ __NR_io_getevents, 5 },
#endif
#ifdef __NR_setxattr
	{ __NR_setxattr, 5 },
#endif
#ifdef __NR_lsetxattr
	{ __NR_lsetxattr, 5 },
#endif
#ifdef __NR_fsetxattr
	{ __NR_fsetxattr, 5 },
#endif
#ifdef __NR_getxattr
	{ __NR_getxattr, 4 },
#endif
#ifdef __NR_lgetxattr
	{ __NR_lgetxattr, 4 },
#endif
#ifdef __NR_fgetxattr
	{ __NR_fgetxattr, 4 },
#endif
#ifdef __NR_listxattr
	{ __NR_listxattr, 3 },
#endif
#ifdef __NR_llistxattr
	{ __NR_llistxattr, 3 },
#endif
#ifdef __NR_flistxattr
	{ __NR_flistxattr, 3 },
#endif
#ifdef __NR_removexattr
	{ __NR_removexattr, 2 },
#endif
#ifdef __NR_lremovexattr
	{ __NR_lremovexattr, 2 },
#endif
#ifdef __NR_fremovexattr
	{ __NR_fremovexattr, 2 },
#endif
#ifdef __NR_getcwd
	{ __NR_getcwd, 2 },
#endif
#ifdef __NR_eventfd2
	{ __NR_eventfd2, 2 },
#endif
#ifdef __NR_epoll_create1
	{ __NR_epoll_create1, 1 },
#endif
#ifdef __NR_epoll_ctl
	{ __NR_epoll_ctl, 4 },
#endif
#ifdef __NR_epoll_pwait
	{ __NR_epoll_pwait, 6 },
#endif
#ifdef __NR_dup
	{ __NR_dup, 1 },
#endif
#ifdef __NR_dup3
	{ __NR_dup3, 3 },
#endif
#ifdef __NR_fcntl
	{ __NR_fcntl, 3 },
#endif
#ifdef __NR_inotify_init1
	{ __NR_inotify_init1, 1 },
#endif
#ifdef __NR_inotify_add_watch
	{ __NR_inotify_add_watch, 3 },
#endif
#ifdef __NR_inotify_rm_watch
	{ __NR_inotify_rm_watch, 2 },
#endif
#ifdef __NR_ioctl
	{ __NR_ioctl, 3 },
#endif
#ifdef __NR_flock
	{ __NR_flock, 2 },
#endif
#ifdef __NR_mknodat
	{ __NR_mknodat, 4 },
#endif
#ifdef __NR_mkdirat
	{ __NR_mkdirat, 3 },
#endif
#ifdef __NR_unlinkat
	{ __NR_unlinkat, 3 },
#endif
#ifdef __NR_symlinkat
	{ __NR_symlinkat, 3 },
#endif
#ifdef __NR_linkat
	{ __NR_linkat, 5 },
#endif
#ifdef __NR_renameat
	{ __NR_renameat, 4 },
#endif
#ifdef __NR_renameat2
	{ __NR_renameat2, 5 },
#endif
#ifdef __NR_umount2
	{ __NR_umount2, 2 },
#endif
#ifdef __NR_mount
	{ __NR_mount, 5 },
#endif
#ifdef __NR_pivot_root
	{ __NR_pivot_root, 2 },
#endif
#ifdef __NR_statfs
	{ __NR_statfs, 2 },
#endif
#ifdef __NR_fstatfs
	{ __NR_fstatfs, 2 },
#endif
#ifdef __NR_truncate
	{ __NR_truncate, 2 },
#endif
#ifdef __NR_ftruncate
	{ __NR_ftruncate, 2 },
#endif
#ifdef __NR_fallocate
	{ __NR_fallocate, 4 },
#endif
#ifdef __NR_faccessat
	{ __NR_faccessat, 3 },
#endif
#ifdef __NR_faccessat2
	{ __NR_faccessat2, 4 },
#endif
#ifdef __NR_chdir
	{ __NR_chdir, 1 },
#endif
#ifdef __NR_fchdir
	{ __NR_fchdir, 1 },
#endif
#ifdef __NR_chroot
	{ __NR_chroot, 1 },
#endif
#ifdef __NR_fchmod
	{ __NR_fchmod, 2 },
#endif
#ifdef __NR_fchmodat
	{ __NR_fchmodat, 3 },
#endif
#ifdef __NR_fchownat
	{ __NR_fchownat, 5 },
#endif
#ifdef __NR_fchown
	{ __NR_fchown, 3 },
#endif
#ifdef __NR_openat
	{ __NR_openat, 4 },
#endif
#ifdef __NR_openat2
	{ __NR_openat2, 4 },
#endif
#ifdef __NR_close
	{ __NR_close, 1 },
#endif
#ifdef __NR_close_range
	{ __NR_close_range, 3 },
#endif
#ifdef __NR_pipe2
	{ __NR_pipe2, 2 },
#endif
#ifdef __NR_getdents64
	{ __NR_getdents64, 3 },
#endif
#ifdef __NR_lseek
	{ __NR_lseek, 3 },
#endif
#ifdef __NR_read
	{ __NR_read, 3 },
#endif
#ifdef __NR_write
	{ __NR_write, 3 },
#endif
#ifdef __NR_readv
	{ __NR_readv, 3 },
#endif
#ifdef __NR_writev
	{ __NR_writev, 3 },
#endif
#ifdef __NR_pread64
	{ __NR_pread64, 4 },
#endif
#ifdef __NR_pwrite64
	{ __NR_pwrite64, 4 },
#endif
#ifdef __NR_preadv
	{ __NR_preadv, 5 },
#endif
#ifdef __NR_pwritev
	{ __NR_pwritev, 5 },
#endif
#ifdef __NR_sendfile
	{ __NR_sendfile, 4 },
#endif
#ifdef __NR_pselect6
	{ __NR_pselect6, 6 },
#endif
#ifdef __NR_ppoll
	{ __NR_ppoll, 5 },
#endif
#ifdef __NR_signalfd4
	{ __NR_signalfd4, 4 },
#endif
#ifdef __NR_vmsplice
	{ __NR_vmsplice, 4 },
#endif
#ifdef __NR_splice
	{ __NR_splice, 6 },
#endif
#ifdef __NR_tee
	{ __NR_tee, 4 },
#endif
#ifdef __NR_readlinkat
	{ __NR_readlinkat, 4 },
#endif
#ifdef __NR_newfstatat
	{ __NR_newfstatat, 4 },
#endif
#ifdef __NR_fstat
	{ __NR_fstat, 2 },
#endif
#ifdef __NR_fsync
	{ __NR_fsync, 1 },
#endif
#ifdef __NR_fdatasync
	{ __NR_fdatasync, 1 },
#endif
#ifdef __NR_sync_file_range
	{ __NR_sync_file_range, 4 },
#endif
#ifdef __NR_timerfd_create
	{ __NR_timerfd_create, 2 },
#endif
#ifdef __NR_timerfd_settime
	{ __NR_timerfd_settime, 4 },
#endif
#ifdef __NR_timerfd_gettime
	{ __NR_timerfd_gettime, 2 },
#endif
#ifdef __NR_utimensat
	{ __NR_utimensat, 4 },
#endif
#ifdef __NR_capget
	{ __NR_capget, 2 },
#endif
#ifdef __NR_capset
	{ __NR_capset, 2 },
#endif
#ifdef __NR_personality
	{ __NR_personality, 1 },
#endif
#ifdef __NR_exit
	{ __NR_exit, 1 },
#endif
#ifdef __NR_exit_group
	{ __NR_exit_group, 1 },
#endif
#ifdef __NR_waitid
	{ __NR_waitid, 5 },
#endif
#ifdef __NR_set_tid_address
	{ __NR_set_tid_address, 1 },
#endif
#ifdef __NR_unshare
	{ __NR_unshare, 1 },
#endif
#ifdef __NR_futex
	{ __NR_futex, 6 },
#endif
#ifdef __NR_set_robust_list
	{ __NR_set_robust_list, 2 },
#endif
#ifdef __NR_get_robust_list
	{ __NR_get_robust_list, 3 },
#endif
#ifdef __NR_nanosleep
	{ __NR_nanosleep, 2 },
#endif
#ifdef __NR_setitimer
	{ __NR_setitimer, 3 },
#endif
#ifdef __NR_getitimer
	{ __NR_getitimer, 2 },
#endif
#ifdef __NR_clock_settime
	{ __NR_clock_settime, 2 },
#endif
#ifdef __NR_clock_gettime
	{ __NR_clock_gettime, 2 },
#endif
#ifdef __NR_clock_getres
	{ __NR_clock_getres, 2 },
#endif
#ifdef __NR_clock_nanosleep
	{ __NR_clock_nanosleep, 4 },
#endif
#ifdef __NR_syslog
	{ __NR_syslog, 3 },
#endif
#ifdef __NR_ptrace
	{ __NR_ptrace, 4 },
#endif
#ifdef __NR_sched_setaffinity
	{ __NR_sched_setaffinity, 3 },
#endif
#ifdef __NR_sched_getaffinity
	{ __NR_sched_getaffinity, 3 },
#endif
#ifdef __NR_sched_yield
	{ __NR_sched_yield, 0 },
#endif
#ifdef __NR_kill
	{ __NR_kill, 2 },
#endif
#ifdef __NR_tkill
	{ __NR_tkill, 2 },
#endif
#ifdef __NR_tgkill
	{ __NR_tgkill, 3 },
#endif
#ifdef __NR_sigaltstack
	{ __NR_sigaltstack, 2 },
#endif
#ifdef __NR_rt_sigaction
	{ __NR_rt_sigaction, 4 },
#endif
#ifdef __NR_rt_sigprocmask
	{ __NR_rt_sigprocmask, 4 },
#endif
#ifdef __NR_rt_sigpending
	{ __NR_rt_sigpending, 2 },
#endif
#ifdef __NR_rt_sigtimedwait
	{ __NR_rt_sigtimedwait, 4 },
#endif
#ifdef __NR_rt_sigqueueinfo
	{ __NR_rt_sigqueueinfo, 3 },
#endif
#ifdef __NR_rt_sigreturn
	{ __NR_rt_sigreturn, 0 },
#endif
#ifdef __NR_setpriority
	{ __NR_setpriority, 3 },
#endif
#ifdef __NR_getpriority
	{ __NR_getpriority, 2 },
#endif
#ifdef __NR_reboot
	{ __NR_reboot, 4 },
#endif
#ifdef __NR_setuid
	{ __NR_setuid, 1 },
#endif
#ifdef __NR_setgid
	{ __NR_setgid, 1 },
#endif
#ifdef __NR_setresuid
	{ __NR_setresuid, 3 },
#endif
#ifdef __NR_getresuid
	{ __NR_getresuid, 3 },
#endif
#ifdef __NR_setresgid
	{ __NR_setresgid, 3 },
#endif
#ifdef __NR_getresgid
	{ __NR_getresgid, 3 },
#endif
#ifdef __NR_setpgid
	{ __NR_setpgid, 2 },
#endif
#ifdef __NR_getpgid
	{ __NR_getpgid, 1 },
#endif
#ifdef __NR_getsid
	{ __NR_getsid, 1 },
#endif
#ifdef __NR_setsid
	{ __NR_setsid, 0 },
#endif
#ifdef __NR_uname
	{ __NR_uname, 1 },
#endif
#ifdef __NR_getrlimit
	{ __NR_getrlimit, 2 },
#endif
#ifdef __NR_setrlimit
	{ __NR_setrlimit, 2 },
#endif
#ifdef __NR_getrusage
	{ __NR_getrusage, 2 },
#endif
#ifdef __NR_umask
	{ __NR_umask, 1 },
#endif
#ifdef __NR_prctl
	{ __NR_prctl, 5 },
#endif
#ifdef __NR_getcpu
	{ __NR_getcpu, 3 },
#endif
#ifdef __NR_gettimeofday
	{ __NR_gettimeofday, 2 },
#endif
#ifdef __NR_settimeofday
	{ __NR_settimeofday, 2 },
#endif
#ifdef __NR_getpid
	{ __NR_getpid, 0 },
#endif
#ifdef __NR_getppid
	{ __NR_getppid, 0 },
#endif
#ifdef __NR_getuid
	{ __NR_getuid, 0 },
#endif
#ifdef __NR_geteuid
	{ __NR_geteuid, 0 },
#endif
#ifdef __NR_getgid
	{ __NR_getgid, 0 },
#endif
#ifdef __NR_getegid
	{ __NR_getegid, 0 },
#endif
#ifdef __NR_gettid
	{ __NR_gettid, 0 },
#endif
#ifdef __NR_sysinfo
	{ __NR_sysinfo, 1 },
#endif
#ifdef __NR_shmget
	{ __NR_shmget, 3 },
#endif
#ifdef __NR_shmctl
	{ __NR_shmctl, 3 },
#endif
#ifdef __NR_shmat
	{ __NR_shmat, 3 },
#endif
#ifdef __NR_shmdt
	{ __NR_shmdt, 1 },
#endif
#ifdef __NR_socket
	{ __NR_socket, 3 },
#endif
#ifdef __NR_socketpair
	{ __NR_socketpair, 4 },
#endif
#ifdef __NR_bind
	{ __NR_bind, 3 },
#endif
#ifdef __NR_listen
	{ __NR_listen, 2 },
#endif
#ifdef __NR_accept
	{ __NR_accept, 3 },
#endif
#ifdef __NR_connect
	{ __NR_connect, 3 },
#endif
#ifdef __NR_getsockname
	{ __NR_getsockname, 3 },
#endif
#ifdef __NR_getpeername
	{ __NR_getpeername, 3 },
#endif
#ifdef __NR_sendto
	{ __NR_sendto, 6 },
#endif
#ifdef __NR_recvfrom
	{ __NR_recvfrom, 6 },
#endif
#ifdef __NR_setsockopt
	{ __NR_setsockopt, 5 },
#endif
#ifdef __NR_getsockopt
	{ __NR_getsockopt, 5 },
#endif
#ifdef __NR_shutdown
	{ __NR_shutdown, 2 },
#endif
#ifdef __NR_sendmsg
	{ __NR_sendmsg, 3 },
#endif
#ifdef __NR_recvmsg
	{ __NR_recvmsg, 3 },
#endif
#ifdef __NR_readahead
	{ __NR_readahead, 3 },
#endif
#ifdef __NR_brk
	{ __NR_brk, 1 },
#endif
#ifdef __NR_munmap
	{ __NR_munmap, 2 },
#endif
#ifdef __NR_mremap
	{ __NR_mremap, 5 },
#endif
#ifdef __NR_clone
	{ __NR_clone, 5 },
#endif
#ifdef __NR_execve
	{ __NR_execve, 3 },
#endif
#ifdef __NR_mmap
	{ __NR_mmap, 6 },
#endif
#ifdef __NR_fadvise64
	{ __NR_fadvise64, 4 },
#endif
#ifdef __NR_mprotect
	{ __NR_mprotect, 3 },
#endif
#ifdef __NR_msync
	{ __NR_msync, 3 },
#endif
#ifdef __NR_mlock
	{ __NR_mlock, 2 },
#endif
#ifdef __NR_munlock
	{ __NR_munlock, 2 },
#endif
#ifdef __NR_mlockall
	{ __NR_mlockall, 1 },
#endif
#ifdef __NR_munlockall
	{ __NR_munlockall, 0 },
#endif
#ifdef __NR_mincore
	{ __NR_mincore, 3 },
#endif
#ifdef __NR_madvise
	{ __NR_madvise, 3 },
#endif
#ifdef __NR_mbind
	{ __NR_mbind, 6 },
#endif
#ifdef __NR_get_mempolicy
	{ __NR_get_mempolicy, 5 },
#endif
#ifdef __NR_set_mempolicy
	{ __NR_set_mempolicy, 3 },
#endif
#ifdef __NR_move_pages
	{ __NR_move_pages, 6 },
#endif
#ifdef __NR_rt_tgsigqueueinfo
	{ __NR_rt_tgsigqueueinfo, 4 },
#endif
#ifdef __NR_perf_event_open
	{ __NR_perf_event_open, 5 },
#endif
#ifdef __NR_accept4
	{ __NR_accept4, 4 },
#endif
#ifdef __NR_recvmmsg
	{ __NR_recvmmsg, 5 },
#endif
#ifdef __NR_wait4
	{ __NR_wait4, 4 },
#endif
#ifdef __NR_prlimit64
	{ __NR_prlimit64, 4 },
#endif
#ifdef __NR_name_to_handle_at
	{ __NR_name_to_handle_at, 5 },
#endif
#ifdef __NR_open_by_handle_at
	{ __NR_open_by_handle_at, 3 },
#endif
#ifdef __NR_syncfs
	{ __NR_syncfs, 1 },
#endif
#ifdef __NR_setns
	{ __NR_setns, 2 },
#endif
#ifdef __NR_sendmmsg
	{ __NR_sendmmsg, 4 },
#endif
#ifdef __NR_process_vm_readv
	{ __NR_process_vm_readv, 6 },
#endif
#ifdef __NR_process_vm_writev
	{ __NR_process_vm_writev, 6 },
#endif
#ifdef __NR_kcmp
	{ __NR_kcmp, 5 },
#endif
#ifdef __NR_finit_module
	{ __NR_finit_module, 3 },
#endif
#ifdef __NR_sched_setattr
	{ __NR_sched_setattr, 3 },
#endif
#ifdef __NR_sched_getattr
	{ __NR_sched_getattr, 4 },
#endif
#ifdef __NR_seccomp
	{ __NR_seccomp, 3 },
#endif
#ifdef __NR_getrandom
	{ __NR_getrandom, 3 },
#endif
#ifdef __NR_memfd_create
	{ __NR_memfd_create, 2 },
#endif
#ifdef __NR_bpf
	{ __NR_bpf, 3 },
#endif
#ifdef __NR_execveat
	{ __NR_execveat, 5 },
#endif
#ifdef __NR_userfaultfd
	{ __NR_userfaultfd, 1 },
#endif
#ifdef __NR_membarrier
	{ __NR_membarrier, 3 },
#endif
#ifdef __NR_mlock2
	{ __NR_mlock2, 3 },
#endif
#ifdef __NR_copy_file_range
	{ __NR_copy_file_range, 6 },
#endif
#ifdef __NR_preadv2
	{ __NR_preadv2, 6 },
#endif
#ifdef __NR_pwritev2
	{ __NR_pwritev2, 6 },
#endif
#ifdef __NR_pkey_mprotect
	{ __NR_pkey_mprotect, 4 },
#endif
#ifdef __NR_pkey_alloc
	{ __NR_pkey_alloc, 2 },
#endif
#ifdef __NR_pkey_free
	{ __NR_pkey_free, 1 },
#endif
#ifdef __NR_statx
	{ __NR_statx, 5 },
#endif
#ifdef __NR_rseq
	{ __NR_rseq, 4 },
#endif
#ifdef __NR_clone3
	{ __NR_clone3, 2 },
#endif
#ifdef __NR_pidfd_open
	{ __NR_pidfd_open, 2 },
#endif
#ifdef __NR_pidfd_getfd
	{ __NR_pidfd_getfd, 3 },
#endif
#ifdef __NR_pidfd_send_signal
	{ __NR_pidfd_send_signal, 4 },
#endif
#ifdef __NR_process_madvise
	{ __NR_process_madvise, 5 },
#endif
#ifdef __NR_epoll_pwait2
	{ __NR_epoll_pwait2, 6 },
#endif
#ifdef __NR_memfd_secret
	{ __NR_memfd_secret, 1 },
#endif
#ifdef __NR_process_mrelease
	{ __NR_process_mrelease, 2 },
#endif
#ifdef __NR_futex_waitv
	{ __NR_futex_waitv, 5 },
#endif
