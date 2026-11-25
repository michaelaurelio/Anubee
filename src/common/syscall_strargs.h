/* syscall_strargs.h
 *
 * Which of args[0..3] hold a const char* (path/string) per syscall: bit i
 * set means args[i] is a string pointer. Included once to initialise a
 * { nr, mask } array; the includer must define A0..A3 as (1u << 0)..(1u << 3).
 * Entries are #ifdef-guarded so the table builds against any sysroot.
 */
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
#ifdef __NR_inotify_add_watch
    { __NR_inotify_add_watch, A1 },
#endif
#ifdef __NR_memfd_create
    { __NR_memfd_create, A0 },
#endif
#ifdef __NR_fgetxattr
    { __NR_fgetxattr, A1 },
#endif
#ifdef __NR_fsetxattr
    { __NR_fsetxattr, A1 },
#endif
#ifdef __NR_fremovexattr
    { __NR_fremovexattr, A1 },
#endif
#ifdef __NR_listxattr
    { __NR_listxattr, A0 },
#endif
#ifdef __NR_llistxattr
    { __NR_llistxattr, A0 },
#endif
#ifdef __NR_lsetxattr
    { __NR_lsetxattr, A0 | A1 },
#endif
#ifdef __NR_removexattr
    { __NR_removexattr, A0 | A1 },
#endif
#ifdef __NR_lremovexattr
    { __NR_lremovexattr, A0 | A1 },
#endif
#ifdef __NR_swapon
    { __NR_swapon, A0 },
#endif
#ifdef __NR_swapoff
    { __NR_swapoff, A0 },
#endif
#ifdef __NR_acct
    { __NR_acct, A0 },
#endif
#ifdef __NR_delete_module
    { __NR_delete_module, A0 },
#endif
#ifdef __NR_fchmodat2
    { __NR_fchmodat2, A1 },
#endif
#ifdef __NR_open_tree
    { __NR_open_tree, A1 },
#endif
#ifdef __NR_fspick
    { __NR_fspick, A1 },
#endif
#ifdef __NR_mount_setattr
    { __NR_mount_setattr, A1 },
#endif
#ifdef __NR_move_mount
    { __NR_move_mount, A1 | A3 },
#endif
#ifdef __NR_fsopen
    { __NR_fsopen, A0 },
#endif
