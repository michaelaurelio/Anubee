// SPDX-License-Identifier: GPL-2.0
// Held file handles of mapped libraries, keyed by (dev, inode). A memfd-backed
// or deleted library has no path to reopen, and /proc/<pid>/map_files disappears
// when the process exits, so a map event opens the file once and keeps the fd
// for later symbolization. See sym_fdhold.h.
#include "common/sym_fdhold.h"
#include "common/maps.h"
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define FDHOLD_MAX 1024
#define FDHOLD_MIN 16

struct fdent {
	uint64_t inode;
	uint32_t dev;
	int fd;             // -1 = empty bucket
	uint64_t last_use;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fdent *g_tab;
static size_t g_nbuckets;   // power of two
static size_t g_cap;        // max held fds
static size_t g_count;
static uint64_t g_tick;
static int g_inited;

static uint64_t fd_hash(uint64_t inode, uint32_t dev)
{
	uint64_t h = inode * 0x9e3779b97f4a7c15ULL;

	h ^= (uint64_t)dev * 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}

// Cap is min(1024, soft RLIMIT_NOFILE / 4), at least 16.
static void fd_init_locked(void)
{
	struct rlimit rl;
	size_t cap, nb, i;

	if (g_inited)
		return;
	g_inited = 1;

	cap = FDHOLD_MAX;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
		cap = (size_t)rl.rlim_cur / 4;
	if (cap > FDHOLD_MAX)
		cap = FDHOLD_MAX;
	if (cap < FDHOLD_MIN)
		cap = FDHOLD_MIN;

	nb = 64;
	while (nb < cap * 2)
		nb *= 2;
	g_tab = calloc(nb, sizeof(*g_tab));
	if (!g_tab)
		return;
	for (i = 0; i < nb; i++)
		g_tab[i].fd = -1;
	g_nbuckets = nb;
	g_cap = cap;
}

static struct fdent *fd_find_locked(uint64_t inode, uint32_t dev)
{
	size_t mask, i, probe;

	if (!g_nbuckets)
		return NULL;
	mask = g_nbuckets - 1;
	i = (size_t)(fd_hash(inode, dev) & mask);
	for (probe = 0; probe < g_nbuckets; probe++) {
		struct fdent *e = &g_tab[i];

		if (e->fd < 0)
			return NULL;
		if (e->inode == inode && e->dev == dev)
			return e;
		i = (i + 1) & mask;
	}
	return NULL;
}

static struct fdent *fd_insert_locked(uint64_t inode, uint32_t dev, int fd)
{
	size_t mask, i;

	if (!g_nbuckets)
		return NULL;
	mask = g_nbuckets - 1;
	i = (size_t)(fd_hash(inode, dev) & mask);
	while (g_tab[i].fd >= 0)
		i = (i + 1) & mask;
	g_tab[i].inode = inode;
	g_tab[i].dev = dev;
	g_tab[i].fd = fd;
	g_tab[i].last_use = ++g_tick;
	g_count++;
	return &g_tab[i];
}

// Close the probe chain after removing bucket i.
static void fd_remove_locked(size_t i)
{
	size_t mask = g_nbuckets - 1;
	size_t j = i;

	for (;;) {
		size_t k;

		j = (j + 1) & mask;
		if (g_tab[j].fd < 0)
			break;
		k = (size_t)(fd_hash(g_tab[j].inode, g_tab[j].dev) & mask);
		if (i <= j) {
			if (i < k && k <= j)
				continue;   // entry must stay at j
		} else {
			if (i < k || k <= j)
				continue;
		}
		g_tab[i] = g_tab[j];
		i = j;
	}
	g_tab[i].fd = -1;
	g_tab[i].inode = 0;
	g_tab[i].dev = 0;
	g_count--;
}

static void fd_evict_locked(void)
{
	size_t i, victim = 0;
	int found = 0;

	for (i = 0; i < g_nbuckets; i++) {
		if (g_tab[i].fd < 0)
			continue;
		if (!found || g_tab[i].last_use < g_tab[victim].last_use) {
			victim = i;
			found = 1;
		}
	}
	if (!found)
		return;
	close(g_tab[victim].fd);
	fd_remove_locked(victim);
}

// Take ownership of fd for the key: dedup, cap and LRU rules apply.
static void fd_hold_locked(uint64_t inode, uint32_t dev, int fd)
{
	struct fdent *e = fd_find_locked(inode, dev);

	if (e) {
		e->last_use = ++g_tick;
		close(fd);
		return;
	}
	while (g_cap && g_count >= g_cap)
		fd_evict_locked();
	if (!fd_insert_locked(inode, dev, fd))
		close(fd);
}

void fdhold_note(int pid, uint64_t start, uint64_t end, uint64_t inode, uint32_t dev)
{
	struct stat st;
	char path[96];
	struct fdent *e;
	int fd;

	if (inode == 0 || pid <= 0)
		return;

	pthread_mutex_lock(&g_lock);
	fd_init_locked();
	e = fd_find_locked(inode, dev);
	if (e) {
		e->last_use = ++g_tick;
		pthread_mutex_unlock(&g_lock);
		return;
	}
	pthread_mutex_unlock(&g_lock);

	// Open outside the lock: a slow map_files lookup must not stall the others.
	anubee_map_files_path(path, sizeof(path), pid, start, end);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return;
	if (fstat(fd, &st) != 0 || (uint64_t)st.st_ino != inode) {
		close(fd);
		return;
	}

	pthread_mutex_lock(&g_lock);
	fd_hold_locked(inode, dev, fd);   // re-check: another thread may have won
	pthread_mutex_unlock(&g_lock);
}

int fdhold_dup(uint64_t inode, uint32_t dev)
{
	struct fdent *e;
	int fd = -1;

	pthread_mutex_lock(&g_lock);
	fd_init_locked();
	e = fd_find_locked(inode, dev);
	if (e) {
		fd = fcntl(e->fd, F_DUPFD_CLOEXEC, 0);
		e->last_use = ++g_tick;
	}
	pthread_mutex_unlock(&g_lock);
	return fd;
}

void fdhold_close_all(void)
{
	size_t i;

	pthread_mutex_lock(&g_lock);
	for (i = 0; g_tab && i < g_nbuckets; i++) {
		if (g_tab[i].fd >= 0) {
			close(g_tab[i].fd);
			g_tab[i].fd = -1;
		}
	}
	g_count = 0;
	pthread_mutex_unlock(&g_lock);
}

void fdhold_put_fd(uint64_t inode, uint32_t dev, int fd)
{
	if (inode == 0 || fd < 0)
		return;
	pthread_mutex_lock(&g_lock);
	fd_init_locked();
	fd_hold_locked(inode, dev, fd);
	pthread_mutex_unlock(&g_lock);
}

size_t fdhold_count(void)
{
	size_t n;

	pthread_mutex_lock(&g_lock);
	n = g_count;
	pthread_mutex_unlock(&g_lock);
	return n;
}
