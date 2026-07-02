// SPDX-License-Identifier: GPL-2.0
// APK-embedded stored (uncompressed) .so display-name resolution. See
// symbolize_internal.h. Parses the ZIP central directory once per APK path.
#include <sys/types.h>
#include "symbolize_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

// ---- APK-embedded .so name resolution ------------------------------------
//
// Android 6+ allows direct mmap of page-aligned stored (uncompressed) .so files
// from inside APKs. When /proc/<pid>/maps shows a mapping backed by a .apk file,
// elf_off (from module_base) is the ELF start inside the APK, matching the
// stored .so's data_start in the ZIP central directory. The symbol resolution via
// dynsym_get(path, elf_off, ...) already works correctly because the APK is
// opened at elf_off to read the ELF. This code only adds the display-name
// refinement: "base.apk -> libfoo.so!func+0x..." instead of "base.apk!...".
//
// The ZIP central directory is parsed once per APK path and cached in a small
// fixed array (APKs typically contain a handful of .so files under lib/).

#define APK_SO_MAX    32
#define APK_CACHE_MAX  8

struct apk_so_entry {
	char     name[128];    // inner .so basename, e.g. "libnative.so"
	uint64_t data_start;   // ELF start byte offset within the APK
	uint64_t size;
};

struct apk_cache {
	char path[MAX_PATH_LEN];
	struct apk_so_entry entries[APK_SO_MAX];
	int count;
};

static struct apk_cache g_apk[APK_CACHE_MAX];
static int g_napk;

static struct apk_cache *apk_parse(const char *path)
{
	if (g_napk >= APK_CACHE_MAX)
		return NULL;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	// Locate EOCD record (signature 50 4b 05 06) by scanning backward.
	off_t fsize = lseek(fd, 0, SEEK_END);
	if (fsize < 22) { close(fd); return NULL; }

	off_t eocd_off = -1;
	uint8_t buf[22];
	off_t limit = fsize - 22 - 65535;
	if (limit < 0) limit = 0;
	for (off_t p = fsize - 22; p >= limit; p--) {
		if (pread_all(fd, buf, 4, p) != 0) break;
		if (buf[0]==0x50 && buf[1]==0x4b && buf[2]==0x05 && buf[3]==0x06) {
			if (pread_all(fd, buf, 22, p) == 0) { eocd_off = p; break; }
		}
	}
	if (eocd_off < 0) { close(fd); return NULL; }

#define APK_LE16(b,o) ((uint16_t)((b)[(o)] | ((unsigned)(b)[(o)+1]<<8)))
#define APK_LE32(b,o) ((uint32_t)((b)[(o)] | ((unsigned)(b)[(o)+1]<<8) | \
                                  ((unsigned)(b)[(o)+2]<<16) | ((unsigned)(b)[(o)+3]<<24)))

	off_t    cd_off      = (off_t)APK_LE32(buf, 16);
	uint16_t num_entries = APK_LE16(buf, 10);

	struct apk_cache *c = &g_apk[g_napk];
	snprintf(c->path, sizeof(c->path), "%s", path);
	c->count = 0;

	off_t cpos = cd_off;
	uint8_t cde[46];
	char fname[256];
	for (int i = 0; i < num_entries && c->count < APK_SO_MAX; i++) {
		if (pread_all(fd, cde, 46, cpos) != 0) break;
		if (cde[0]!=0x50 || cde[1]!=0x4b || cde[2]!=0x01 || cde[3]!=0x02) break;
		cpos += 46;

		uint16_t method    = APK_LE16(cde, 10);
		uint32_t comp_size = APK_LE32(cde, 20);
		uint16_t fname_len = APK_LE16(cde, 28);
		uint16_t extra_len = APK_LE16(cde, 30);
		uint16_t cmt_len   = APK_LE16(cde, 32);
		uint32_t lhdr_off  = APK_LE32(cde, 42);

		uint16_t rlen = fname_len < 255 ? fname_len : 255;
		ssize_t  n    = pread(fd, fname, rlen, cpos);
		if (n < 0) break;
		fname[n] = '\0';
		cpos += (off_t)fname_len + extra_len + cmt_len;

		// Only stored (uncompressed) .so files under lib/
		if (method != 0) continue;
		if (strncmp(fname, "lib/", 4) != 0) continue;
		const char *base = strrchr(fname, '/');
		base = base ? base + 1 : fname;
		size_t blen = strlen(base);
		if (blen < 4 || strcmp(base + blen - 3, ".so") != 0) continue;

		// Local file header gives the actual extra field length (may differ from CD).
		uint8_t lfh[30];
		if (pread_all(fd, lfh, 30, (off_t)lhdr_off) != 0) continue;
		if (lfh[0]!=0x50 || lfh[1]!=0x4b || lfh[2]!=0x03 || lfh[3]!=0x04) continue;
		uint64_t data_start = (uint64_t)lhdr_off + 30 + APK_LE16(lfh, 26) + APK_LE16(lfh, 28);

		struct apk_so_entry *e = &c->entries[c->count++];
		snprintf(e->name, sizeof(e->name), "%s", base);
		e->data_start = data_start;
		e->size       = (uint64_t)comp_size;
	}

#undef APK_LE16
#undef APK_LE32

	close(fd);
	g_napk++;
	return c;
}

static struct apk_cache *apk_get(const char *path)
{
	for (int i = 0; i < g_napk; i++)
		if (strcmp(g_apk[i].path, path) == 0)
			return &g_apk[i];
	return apk_parse(path);
}

// Return the inner .so basename for a stored .so mapped from an APK at elf_off,
// or NULL if the path is not an APK or the offset doesn't match any entry.
const char *apk_so_name(const char *path, uint64_t elf_off)
{
	size_t plen = strlen(path);
	if (plen < 4 || strcmp(path + plen - 4, ".apk") != 0)
		return NULL;
	struct apk_cache *c = apk_get(path);
	if (!c)
		return NULL;
	for (int i = 0; i < c->count; i++)
		if (c->entries[i].data_start == elf_off)
			return c->entries[i].name;
	return NULL;
}
