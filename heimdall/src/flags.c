// flags.c — see flags.h.
//
// Flag values are arch-specific (e.g. O_DIRECTORY, O_CLOEXEC differ across
// arches). We reference them by macro name so the cross-compiler fills in the
// target's (arm64) values; rare macros are #ifdef-guarded so the table still
// builds against any sysroot.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE              // expose CLONE_*, O_*, MAP_*, MADV_* extensions
#endif

#include "flags.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#ifdef __has_include
#  if __has_include(<sys/prctl.h>)
#    include <sys/prctl.h>
#  endif
#  if __has_include(<linux/memfd.h>)
#    include <linux/memfd.h>
#  endif
#endif

struct flagdef { unsigned long long val; const char *name; };
#define F(x) { (unsigned long long)(x), #x }
#define NELEMS(a) (sizeof(a) / sizeof((a)[0]))

// ---- generic formatters --------------------------------------------------

// Append matched flag names (OR of bits) into out; return the leftover bits.
static unsigned long long bits_str(unsigned long long v, const struct flagdef *t,
				    size_t n, char *out, size_t outsz)
{
	out[0] = '\0';
	size_t pos = 0;
	int first = 1;
	unsigned long long rem = v;
	for (size_t i = 0; i < n; i++) {
		if (t[i].val == 0 || (rem & t[i].val) != t[i].val)
			continue;
		int w = snprintf(out + pos, outsz - pos, "%s%s", first ? "" : "|", t[i].name);
		if (w > 0 && (size_t)w < outsz - pos)
			pos += (size_t)w;
		first = 0;
		rem &= ~t[i].val;
	}
	return rem;
}

static void dec_bits(unsigned long long v, const struct flagdef *t, size_t n,
		     const char *zero, char *out, size_t outsz)
{
	char buf[256];
	unsigned long long rem = bits_str(v, t, n, buf, sizeof(buf));
	if (buf[0] == '\0') {
		if (v == 0 && zero)
			snprintf(out, outsz, "%s", zero);
		else
			snprintf(out, outsz, "0x%llx", v);
	} else if (rem) {
		snprintf(out, outsz, "%s|0x%llx", buf, rem);
	} else {
		snprintf(out, outsz, "%s", buf);
	}
}

static void dec_enum(unsigned long long v, const struct flagdef *t, size_t n,
		     char *out, size_t outsz)
{
	for (size_t i = 0; i < n; i++)
		if (t[i].val == v) {
			snprintf(out, outsz, "%s", t[i].name);
			return;
		}
	snprintf(out, outsz, "0x%llx", v);
}

// ---- tables --------------------------------------------------------------

static const struct flagdef t_prot[] = {
	F(PROT_READ), F(PROT_WRITE), F(PROT_EXEC),
#ifdef PROT_SEM
	F(PROT_SEM),
#endif
#ifdef PROT_GROWSDOWN
	F(PROT_GROWSDOWN),
#endif
#ifdef PROT_GROWSUP
	F(PROT_GROWSUP),
#endif
#ifdef PROT_BTI
	F(PROT_BTI),
#endif
};

static const struct flagdef t_map[] = {
	F(MAP_SHARED), F(MAP_PRIVATE),
#ifdef MAP_SHARED_VALIDATE
	F(MAP_SHARED_VALIDATE),
#endif
	F(MAP_FIXED), F(MAP_ANONYMOUS),
#ifdef MAP_NORESERVE
	F(MAP_NORESERVE),
#endif
#ifdef MAP_POPULATE
	F(MAP_POPULATE),
#endif
#ifdef MAP_GROWSDOWN
	F(MAP_GROWSDOWN),
#endif
#ifdef MAP_DENYWRITE
	F(MAP_DENYWRITE),
#endif
#ifdef MAP_LOCKED
	F(MAP_LOCKED),
#endif
#ifdef MAP_NONBLOCK
	F(MAP_NONBLOCK),
#endif
#ifdef MAP_STACK
	F(MAP_STACK),
#endif
#ifdef MAP_HUGETLB
	F(MAP_HUGETLB),
#endif
#ifdef MAP_FIXED_NOREPLACE
	F(MAP_FIXED_NOREPLACE),
#endif
};

// O_* flags excluding the low 2 access-mode bits (handled in dec_open).
static const struct flagdef t_oflags[] = {
	F(O_CREAT), F(O_EXCL), F(O_NOCTTY), F(O_TRUNC), F(O_APPEND), F(O_NONBLOCK),
	F(O_DSYNC), F(O_CLOEXEC),
#ifdef O_DIRECTORY
	F(O_DIRECTORY),
#endif
#ifdef O_NOFOLLOW
	F(O_NOFOLLOW),
#endif
#ifdef O_DIRECT
	F(O_DIRECT),
#endif
#ifdef O_LARGEFILE
	F(O_LARGEFILE),
#endif
#ifdef O_PATH
	F(O_PATH),
#endif
#ifdef O_TMPFILE
	F(O_TMPFILE),
#endif
#ifdef O_NOATIME
	F(O_NOATIME),
#endif
#ifdef __O_SYNC
	{ (unsigned long long)__O_SYNC, "O_SYNC" },
#endif
};

// Flags shared by pipe2/dup3/eventfd2/inotify_init1/accept4/... (SOCK_* alias O_*).
static const struct flagdef t_cloexec[] = {
	F(O_CLOEXEC), F(O_NONBLOCK),
#ifdef O_DIRECT
	F(O_DIRECT),
#endif
};

static const struct flagdef t_msg[] = {
#ifdef MSG_OOB
	F(MSG_OOB),
#endif
#ifdef MSG_PEEK
	F(MSG_PEEK),
#endif
#ifdef MSG_DONTROUTE
	F(MSG_DONTROUTE),
#endif
#ifdef MSG_CTRUNC
	F(MSG_CTRUNC),
#endif
#ifdef MSG_TRUNC
	F(MSG_TRUNC),
#endif
#ifdef MSG_DONTWAIT
	F(MSG_DONTWAIT),
#endif
#ifdef MSG_EOR
	F(MSG_EOR),
#endif
#ifdef MSG_WAITALL
	F(MSG_WAITALL),
#endif
#ifdef MSG_NOSIGNAL
	F(MSG_NOSIGNAL),
#endif
#ifdef MSG_MORE
	F(MSG_MORE),
#endif
#ifdef MSG_CMSG_CLOEXEC
	F(MSG_CMSG_CLOEXEC),
#endif
};

static const struct flagdef t_at[] = {
#ifdef AT_SYMLINK_NOFOLLOW
	F(AT_SYMLINK_NOFOLLOW),
#endif
#ifdef AT_REMOVEDIR
	F(AT_REMOVEDIR),
#endif
#ifdef AT_SYMLINK_FOLLOW
	F(AT_SYMLINK_FOLLOW),
#endif
#ifdef AT_NO_AUTOMOUNT
	F(AT_NO_AUTOMOUNT),
#endif
#ifdef AT_EMPTY_PATH
	F(AT_EMPTY_PATH),
#endif
#ifdef AT_EACCESS
	F(AT_EACCESS),
#endif
};

static const struct flagdef t_access[] = { F(R_OK), F(W_OK), F(X_OK) };

static const struct flagdef t_clone[] = {
	F(CLONE_VM), F(CLONE_FS), F(CLONE_FILES), F(CLONE_SIGHAND), F(CLONE_PTRACE),
	F(CLONE_VFORK), F(CLONE_PARENT), F(CLONE_THREAD), F(CLONE_NEWNS), F(CLONE_SYSVSEM),
	F(CLONE_SETTLS), F(CLONE_PARENT_SETTID), F(CLONE_CHILD_CLEARTID),
	F(CLONE_UNTRACED), F(CLONE_CHILD_SETTID),
#ifdef CLONE_NEWCGROUP
	F(CLONE_NEWCGROUP),
#endif
#ifdef CLONE_NEWUTS
	F(CLONE_NEWUTS), F(CLONE_NEWIPC), F(CLONE_NEWUSER), F(CLONE_NEWPID), F(CLONE_NEWNET), F(CLONE_IO),
#endif
};

static const struct flagdef t_madv[] = {
	F(MADV_NORMAL), F(MADV_RANDOM), F(MADV_SEQUENTIAL), F(MADV_WILLNEED),
	F(MADV_DONTNEED),
#ifdef MADV_FREE
	F(MADV_FREE),
#endif
#ifdef MADV_REMOVE
	F(MADV_REMOVE), F(MADV_DONTFORK), F(MADV_DOFORK),
#endif
#ifdef MADV_HUGEPAGE
	F(MADV_HUGEPAGE), F(MADV_NOHUGEPAGE),
#endif
#ifdef MADV_DONTDUMP
	F(MADV_DONTDUMP), F(MADV_DODUMP),
#endif
#ifdef MADV_WIPEONFORK
	F(MADV_WIPEONFORK), F(MADV_KEEPONFORK),
#endif
#ifdef MADV_COLD
	F(MADV_COLD), F(MADV_PAGEOUT),
#endif
};

static const struct flagdef t_whence[] = {
	F(SEEK_SET), F(SEEK_CUR), F(SEEK_END),
#ifdef SEEK_DATA
	F(SEEK_DATA), F(SEEK_HOLE),
#endif
};

static const struct flagdef t_fcntl[] = {
	F(F_DUPFD), F(F_GETFD), F(F_SETFD), F(F_GETFL), F(F_SETFL),
	F(F_GETLK), F(F_SETLK), F(F_SETLKW), F(F_GETOWN), F(F_SETOWN),
#ifdef F_DUPFD_CLOEXEC
	F(F_DUPFD_CLOEXEC),
#endif
#ifdef F_SETPIPE_SZ
	F(F_SETPIPE_SZ), F(F_GETPIPE_SZ),
#endif
#ifdef F_ADD_SEALS
	F(F_ADD_SEALS), F(F_GET_SEALS),
#endif
#ifdef F_GETSIG
	F(F_GETSIG), F(F_SETSIG),
#endif
};

static const struct flagdef t_af[] = {
	F(AF_UNSPEC), F(AF_UNIX), F(AF_INET), F(AF_INET6),
#ifdef AF_NETLINK
	F(AF_NETLINK),
#endif
#ifdef AF_PACKET
	F(AF_PACKET),
#endif
#ifdef AF_BLUETOOTH
	F(AF_BLUETOOTH),
#endif
#ifdef AF_VSOCK
	F(AF_VSOCK),
#endif
};

static const struct flagdef t_socktype[] = {
	F(SOCK_STREAM), F(SOCK_DGRAM), F(SOCK_RAW), F(SOCK_SEQPACKET),
#ifdef SOCK_RDM
	F(SOCK_RDM),
#endif
};

#ifdef PR_SET_NAME
static const struct flagdef t_prctl[] = {
	F(PR_SET_PDEATHSIG), F(PR_GET_PDEATHSIG), F(PR_GET_DUMPABLE), F(PR_SET_DUMPABLE),
	F(PR_GET_KEEPCAPS), F(PR_SET_KEEPCAPS), F(PR_SET_NAME), F(PR_GET_NAME),
#ifdef PR_GET_SECCOMP
	F(PR_GET_SECCOMP), F(PR_SET_SECCOMP),
#endif
#ifdef PR_CAPBSET_READ
	F(PR_CAPBSET_READ), F(PR_CAPBSET_DROP),
#endif
#ifdef PR_SET_NO_NEW_PRIVS
	F(PR_SET_NO_NEW_PRIVS), F(PR_GET_NO_NEW_PRIVS),
#endif
#ifdef PR_SET_PTRACER
	F(PR_SET_PTRACER),
#endif
#ifdef PR_SET_TIMERSLACK
	F(PR_SET_TIMERSLACK), F(PR_GET_TIMERSLACK),
#endif
#ifdef PR_SET_VMA
	F(PR_SET_VMA),
#endif
};
#endif

#ifdef MFD_CLOEXEC
static const struct flagdef t_mfd[] = {
	F(MFD_CLOEXEC),
#ifdef MFD_ALLOW_SEALING
	F(MFD_ALLOW_SEALING),
#endif
#ifdef MFD_HUGETLB
	F(MFD_HUGETLB),
#endif
};
#endif

// ---- specialised decoders ------------------------------------------------

static void dec_open(unsigned long long v, char *out, size_t n)
{
	const char *acc = (v & 3) == 0 ? "O_RDONLY" :
			  (v & 3) == 1 ? "O_WRONLY" :
			  (v & 3) == 2 ? "O_RDWR" : "O_ACCMODE";
	char buf[256];
	unsigned long long rem = bits_str(v & ~3ULL, t_oflags, NELEMS(t_oflags), buf, sizeof(buf));
	if (buf[0] && rem)
		snprintf(out, n, "%s|%s|0x%llx", acc, buf, rem);
	else if (buf[0])
		snprintf(out, n, "%s|%s", acc, buf);
	else if (rem)
		snprintf(out, n, "%s|0x%llx", acc, rem);
	else
		snprintf(out, n, "%s", acc);
}

static void dec_socktype(unsigned long long v, char *out, size_t n)
{
	unsigned long long flags = 0;
#ifdef SOCK_NONBLOCK
	flags |= SOCK_NONBLOCK;
#endif
#ifdef SOCK_CLOEXEC
	flags |= SOCK_CLOEXEC;
#endif
	unsigned long long base = v & ~flags;
	char b[64];
	dec_enum(base, t_socktype, NELEMS(t_socktype), b, sizeof(b));
	char fbuf[64];
	fbuf[0] = '\0';
	size_t pos = 0;
#ifdef SOCK_NONBLOCK
	if (v & SOCK_NONBLOCK) pos += snprintf(fbuf + pos, sizeof(fbuf) - pos, "|SOCK_NONBLOCK");
#endif
#ifdef SOCK_CLOEXEC
	if (v & SOCK_CLOEXEC) pos += snprintf(fbuf + pos, sizeof(fbuf) - pos, "|SOCK_CLOEXEC");
#endif
	snprintf(out, n, "%s%s", b, fbuf);
}

static const char *signame(unsigned long long s)
{
	static const struct flagdef sig[] = {
		F(SIGHUP), F(SIGINT), F(SIGQUIT), F(SIGILL), F(SIGTRAP), F(SIGABRT),
		F(SIGBUS), F(SIGFPE), F(SIGKILL), F(SIGUSR1), F(SIGSEGV), F(SIGUSR2),
		F(SIGPIPE), F(SIGALRM), F(SIGTERM), F(SIGCHLD), F(SIGCONT), F(SIGSTOP),
		F(SIGTSTP), F(SIGTTIN), F(SIGTTOU), F(SIGURG), F(SIGXCPU), F(SIGXFSZ),
		F(SIGVTALRM), F(SIGPROF), F(SIGWINCH), F(SIGIO), F(SIGSYS),
	};
	for (size_t i = 0; i < NELEMS(sig); i++)
		if (sig[i].val == s)
			return sig[i].name;
	return NULL;
}

static void dec_signal(unsigned long long v, char *out, size_t n)
{
	const char *s = signame(v);
	if (s)
		snprintf(out, n, "%s", s);
#ifdef SIGRTMIN
	else if (v >= (unsigned long long)SIGRTMIN && v <= 64)
		snprintf(out, n, "SIGRT%llu", v - (unsigned long long)SIGRTMIN);
#endif
	else
		snprintf(out, n, "%llu", v);
}

static void dec_clone(unsigned long long v, char *out, size_t n)
{
	char buf[256];
	unsigned long long rem = bits_str(v & ~0xffULL, t_clone, NELEMS(t_clone), buf, sizeof(buf));
	char sigpart[32];
	sigpart[0] = '\0';
	unsigned long long exitsig = v & 0xff;
	if (exitsig)
		dec_signal(exitsig, sigpart, sizeof(sigpart));
	// Assemble: flags [| leftover] [| exit-signal]
	size_t pos = 0;
	out[0] = '\0';
	if (buf[0])
		pos += snprintf(out + pos, n - pos, "%s", buf);
	if (rem)
		pos += snprintf(out + pos, n - pos, "%s0x%llx", pos ? "|" : "", rem);
	if (sigpart[0])
		snprintf(out + pos, n - pos, "%s%s", pos ? "|" : "", sigpart);
	if (!out[0])
		snprintf(out, n, "0");
}

static void dec_mode(unsigned long long v, char *out, size_t n)
{
	snprintf(out, n, "0%llo", v);   // octal file mode
}

// ---- dispatch ------------------------------------------------------------

int flags_decode_arg(long nr, int arg, unsigned long long v, char *out, size_t outsz)
{
	switch (nr) {
#ifdef __NR_openat
	case __NR_openat:
		if (arg == 2) { dec_open(v, out, outsz); return 1; }
		if (arg == 3) { dec_mode(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_mmap
	case __NR_mmap:
		if (arg == 2) { dec_bits(v, t_prot, NELEMS(t_prot), "PROT_NONE", out, outsz); return 1; }
		if (arg == 3) { dec_bits(v, t_map, NELEMS(t_map), NULL, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_mprotect
	case __NR_mprotect:
		if (arg == 2) { dec_bits(v, t_prot, NELEMS(t_prot), "PROT_NONE", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_pkey_mprotect
	case __NR_pkey_mprotect:
		if (arg == 2) { dec_bits(v, t_prot, NELEMS(t_prot), "PROT_NONE", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_mremap
	case __NR_mremap:
		if (arg == 3) {
			static const struct flagdef t[] = {
#ifdef MREMAP_MAYMOVE
				F(MREMAP_MAYMOVE),
#endif
#ifdef MREMAP_FIXED
				F(MREMAP_FIXED),
#endif
			};
			dec_bits(v, t, NELEMS(t), "0", out, outsz); return 1;
		}
		break;
#endif
#ifdef __NR_madvise
	case __NR_madvise:
		if (arg == 2) { dec_enum(v, t_madv, NELEMS(t_madv), out, outsz); return 1; }
		break;
#endif
#ifdef __NR_lseek
	case __NR_lseek:
		if (arg == 2) { dec_enum(v, t_whence, NELEMS(t_whence), out, outsz); return 1; }
		break;
#endif
#ifdef __NR_fcntl
	case __NR_fcntl:
		if (arg == 1) { dec_enum(v, t_fcntl, NELEMS(t_fcntl), out, outsz); return 1; }
		break;
#endif
#ifdef __NR_socket
	case __NR_socket:
		if (arg == 0) { dec_enum(v, t_af, NELEMS(t_af), out, outsz); return 1; }
		if (arg == 1) { dec_socktype(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_socketpair
	case __NR_socketpair:
		if (arg == 0) { dec_enum(v, t_af, NELEMS(t_af), out, outsz); return 1; }
		if (arg == 1) { dec_socktype(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_faccessat
	case __NR_faccessat:
		if (arg == 2) { dec_bits(v, t_access, NELEMS(t_access), "F_OK", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_faccessat2
	case __NR_faccessat2:
		if (arg == 2) { dec_bits(v, t_access, NELEMS(t_access), "F_OK", out, outsz); return 1; }
		if (arg == 3) { dec_bits(v, t_at, NELEMS(t_at), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_newfstatat
	case __NR_newfstatat:
		if (arg == 3) { dec_bits(v, t_at, NELEMS(t_at), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_statx
	case __NR_statx:
		if (arg == 2) { dec_bits(v, t_at, NELEMS(t_at), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_unlinkat
	case __NR_unlinkat:
		if (arg == 2) { dec_bits(v, t_at, NELEMS(t_at), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_fchownat
	case __NR_fchownat:
		if (arg == 4) { dec_bits(v, t_at, NELEMS(t_at), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_linkat
	case __NR_linkat:
		if (arg == 4) { dec_bits(v, t_at, NELEMS(t_at), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_mkdirat
	case __NR_mkdirat:
		if (arg == 2) { dec_mode(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_fchmodat
	case __NR_fchmodat:
		if (arg == 2) { dec_mode(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_fchmod
	case __NR_fchmod:
		if (arg == 1) { dec_mode(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_pipe2
	case __NR_pipe2:
		if (arg == 1) { dec_bits(v, t_cloexec, NELEMS(t_cloexec), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_dup3
	case __NR_dup3:
		if (arg == 2) { dec_bits(v, t_cloexec, NELEMS(t_cloexec), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_eventfd2
	case __NR_eventfd2:
		if (arg == 1) { dec_bits(v, t_cloexec, NELEMS(t_cloexec), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_inotify_init1
	case __NR_inotify_init1:
		if (arg == 0) { dec_bits(v, t_cloexec, NELEMS(t_cloexec), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_accept4
	case __NR_accept4:
		if (arg == 3) { dec_socktype(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_sendto
	case __NR_sendto:
		if (arg == 3) { dec_bits(v, t_msg, NELEMS(t_msg), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_recvfrom
	case __NR_recvfrom:
		if (arg == 3) { dec_bits(v, t_msg, NELEMS(t_msg), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_sendmsg
	case __NR_sendmsg:
		if (arg == 2) { dec_bits(v, t_msg, NELEMS(t_msg), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_recvmsg
	case __NR_recvmsg:
		if (arg == 2) { dec_bits(v, t_msg, NELEMS(t_msg), "0", out, outsz); return 1; }
		break;
#endif
#ifdef __NR_clone
	case __NR_clone:
		if (arg == 0) { dec_clone(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_kill
	case __NR_kill:
		if (arg == 1) { dec_signal(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_tkill
	case __NR_tkill:
		if (arg == 1) { dec_signal(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_tgkill
	case __NR_tgkill:
		if (arg == 2) { dec_signal(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_rt_sigaction
	case __NR_rt_sigaction:
		if (arg == 0) { dec_signal(v, out, outsz); return 1; }
		break;
#endif
#ifdef __NR_memfd_create
	case __NR_memfd_create:
#ifdef MFD_CLOEXEC
		if (arg == 1) { dec_bits(v, t_mfd, NELEMS(t_mfd), "0", out, outsz); return 1; }
#endif
		break;
#endif
#if defined(__NR_prctl) && defined(PR_SET_NAME)
	case __NR_prctl:
		if (arg == 0) { dec_enum(v, t_prctl, NELEMS(t_prctl), out, outsz); return 1; }
		break;
#endif
	default:
		break;
	}
	return 0;
}
