// SPDX-License-Identifier: GPL-2.0
// See binder_names_load.h.
#include <fcntl.h>
#include <glob.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "modules/binder_names_load.h"

// Mapped jars are deliberately never unmapped: method names point into them
// and analyzers print summaries after teardown. Process exit releases them.
static int load_jar(struct binder_names *bn, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return 0; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return 0;
    if (binder_names_add_jar(bn, m, (size_t)st.st_size) > 0)
        return 1;                      // names point into it: keep mapped
    munmap(m, (size_t)st.st_size);
    return 0;
}

struct binder_names *binder_names_load_device(int *njars)
{
    int n = 0;
    struct binder_names *bn = binder_names_new();
    if (bn) {
        n += load_jar(bn, "/system/framework/framework.jar");
        glob_t gl;
        if (glob("/apex/*/javalib/framework-*.jar", 0, NULL, &gl) == 0) {
            for (size_t i = 0; i < gl.gl_pathc; i++)
                if (!strchr(gl.gl_pathv[i] + 6, '@'))   // skip versioned duplicate mounts
                    n += load_jar(bn, gl.gl_pathv[i]);
            globfree(&gl);
        }
    }
    if (njars) *njars = n;
    return bn;
}
