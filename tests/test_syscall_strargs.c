// Host unit test for the syscall string-argument table
// (common/syscall_strargs.h) that src/common/syscall_argtypes.c's g_str_args[]
// serves. Loads the shared table directly (the C file itself pulls in
// <bpf/bpf.h>, unavailable without the cross-built libbpf) and checks both the
// newly added path-string syscalls and the entries that moved out of the C
// file, plus table structure.
#include <stdio.h>
#include <sys/syscall.h>

#define A0 (1u << 0)
#define A1 (1u << 1)
#define A2 (1u << 2)
#define A3 (1u << 3)

struct entry { long nr; unsigned char mask; };
static const struct entry g_str[] = {
#include "common/syscall_strargs.h"
};
static const int g_count = (int)(sizeof(g_str) / sizeof(g_str[0]));

static unsigned char mask_of(long nr) {
    for (int i = 0; i < g_count; i++)
        if (g_str[i].nr == nr) return g_str[i].mask;
    return 0;
}

static int failures;

static void check(int cond, const char *msg) {
    if (!cond) { printf("FAIL: %s\n", msg); failures++; }
}

int main(void) {
#ifdef __NR_inotify_add_watch
    check(mask_of(__NR_inotify_add_watch) == A1, "inotify_add_watch uses A1");
#endif
#ifdef __NR_memfd_create
    check(mask_of(__NR_memfd_create) == A0, "memfd_create uses A0");
#endif
#ifdef __NR_fgetxattr
    check(mask_of(__NR_fgetxattr) == A1, "fgetxattr uses A1");
#endif
#ifdef __NR_fsetxattr
    check(mask_of(__NR_fsetxattr) == A1, "fsetxattr uses A1");
#endif
#ifdef __NR_fremovexattr
    check(mask_of(__NR_fremovexattr) == A1, "fremovexattr uses A1");
#endif
#ifdef __NR_listxattr
    check(mask_of(__NR_listxattr) == A0, "listxattr uses A0");
#endif
#ifdef __NR_llistxattr
    check(mask_of(__NR_llistxattr) == A0, "llistxattr uses A0");
#endif
#ifdef __NR_lsetxattr
    check(mask_of(__NR_lsetxattr) == (A0 | A1), "lsetxattr uses A0|A1");
#endif
#ifdef __NR_removexattr
    check(mask_of(__NR_removexattr) == (A0 | A1), "removexattr uses A0|A1");
#endif
#ifdef __NR_lremovexattr
    check(mask_of(__NR_lremovexattr) == (A0 | A1), "lremovexattr uses A0|A1");
#endif
#ifdef __NR_swapon
    check(mask_of(__NR_swapon) == A0, "swapon uses A0");
#endif
#ifdef __NR_swapoff
    check(mask_of(__NR_swapoff) == A0, "swapoff uses A0");
#endif
#ifdef __NR_acct
    check(mask_of(__NR_acct) == A0, "acct uses A0");
#endif
#ifdef __NR_delete_module
    check(mask_of(__NR_delete_module) == A0, "delete_module uses A0");
#endif
#ifdef __NR_fchmodat2
    check(mask_of(__NR_fchmodat2) == A1, "fchmodat2 uses A1");
#endif
#ifdef __NR_open_tree
    check(mask_of(__NR_open_tree) == A1, "open_tree uses A1");
#endif
#ifdef __NR_fspick
    check(mask_of(__NR_fspick) == A1, "fspick uses A1");
#endif
#ifdef __NR_mount_setattr
    check(mask_of(__NR_mount_setattr) == A1, "mount_setattr uses A1");
#endif
#ifdef __NR_move_mount
    check(mask_of(__NR_move_mount) == (A1 | A3), "move_mount uses A1|A3");
#endif
#ifdef __NR_fsopen
    check(mask_of(__NR_fsopen) == A0, "fsopen uses A0");
#endif

    // Regression: entries that previously lived in syscall_argtypes.c.
#ifdef __NR_openat
    check(mask_of(__NR_openat) == A1, "openat uses A1");
#endif
#ifdef __NR_openat2
    check(mask_of(__NR_openat2) == A1, "openat2 uses A1");
#endif
#ifdef __NR_renameat
    check(mask_of(__NR_renameat) == (A1 | A3), "renameat uses A1|A3");
#endif
#ifdef __NR_linkat
    check(mask_of(__NR_linkat) == (A1 | A3), "linkat uses A1|A3");
#endif
#ifdef __NR_symlinkat
    check(mask_of(__NR_symlinkat) == (A0 | A2), "symlinkat uses A0|A2");
#endif
#ifdef __NR_execve
    check(mask_of(__NR_execve) == A0, "execve uses A0");
#endif
#ifdef __NR_execveat
    check(mask_of(__NR_execveat) == A1, "execveat uses A1");
#endif
#ifdef __NR_statfs
    check(mask_of(__NR_statfs) == A0, "statfs uses A0");
#endif
#ifdef __NR_getxattr
    check(mask_of(__NR_getxattr) == (A0 | A1), "getxattr uses A0|A1");
#endif
#ifdef __NR_lgetxattr
    check(mask_of(__NR_lgetxattr) == (A0 | A1), "lgetxattr uses A0|A1");
#endif
#ifdef __NR_setxattr
    check(mask_of(__NR_setxattr) == (A0 | A1), "setxattr uses A0|A1");
#endif
#ifdef __NR_mount
    check(mask_of(__NR_mount) == (A0 | A1 | A2), "mount uses A0|A1|A2");
#endif
#ifdef __NR_umount2
    check(mask_of(__NR_umount2) == A0, "umount2 uses A0");
#endif
#ifdef __NR_pivot_root
    check(mask_of(__NR_pivot_root) == (A0 | A1), "pivot_root uses A0|A1");
#endif
#ifdef __NR_faccessat
    check(mask_of(__NR_faccessat) == A1, "faccessat uses A1");
#endif
#ifdef __NR_newfstatat
    check(mask_of(__NR_newfstatat) == A1, "newfstatat uses A1");
#endif
#ifdef __NR_readlinkat
    check(mask_of(__NR_readlinkat) == A1, "readlinkat uses A1");
#endif

    // Structure: unique syscall numbers, non-zero masks restricted to A0..A3.
    for (int i = 0; i < g_count; i++) {
        check(g_str[i].mask != 0, "table mask is non-zero");
        check((g_str[i].mask & ~0xfu) == 0, "table mask fits in A0..A3");
        for (int j = 0; j < i; j++)
            check(g_str[i].nr != g_str[j].nr, "table has no duplicate syscall nr");
    }

    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("all checks passed\n");
    return 0;
}
