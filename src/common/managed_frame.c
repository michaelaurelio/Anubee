// SPDX-License-Identifier: GPL-2.0
// Pure managed-frame chain builder + bounded stack_id cache. No libbpf/symbolizer
// deps so the host test links it directly. The impure resolver ares_managed_chain
// and ares_emit_cfi_stack_json live in symbolize.c (they need sym_resolve/CFI).
#include "common/managed_frame.h"
#include "common/emit.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// A managed (AOT/dex-backed) frame resolves as "module!pkg.Class.method"
// (e.g. "boot.oat!android.os.BinderProxy.transact"). Return the method part, or
// NULL if the symbol is not a managed frame.
static const char *managed_method(const char *sym)
{
    if (!sym) return NULL;
    // The JNI bridge lives in boot.oat, so it resolves as
    // "boot.oat!art_jni_trampoline+.." and would match the .oat! test below — but
    // it is a native->managed bridge, not a Java method. Exclude it, mirroring the
    // kind-classifier precedence in ares_emit_cfi_stack_json (jni-trampoline first).
    if (strstr(sym, "art_jni_trampoline")) return NULL;
    if (!strstr(sym, ".oat!") && !strstr(sym, ".odex!") && !strstr(sym, ".vdex!"))
        return NULL;
    const char *bang = strrchr(sym, '!');
    return bang ? bang + 1 : NULL;
}

// ART interpreter entrypoints — a Java method is being interpreted here and has
// no native frame of its own. Shared by syscalls.c and symbolize.c.
int ares_is_interp_frame(const char *sym)
{
    return sym && (strstr(sym, "ToInterpreterBridge") ||
                   strstr(sym, "nterp_helper")         ||
                   strstr(sym, "ExecuteNterpImpl")     ||
                   strstr(sym, "ExecuteSwitchImpl")    ||
                   strstr(sym, "artInterpreterToCompiledCodeBridge"));
}

int ares_managed_chain_build(const char *const *syms, int n,
                             const char *const *nterp_names, int nterp_n,
                             char *out, size_t cap)
{
    struct jbuf j = {0};
    int count = 0;
    jb_c(&j, '[');
    for (int i = 0; i < n; i++) {
        const char *m = managed_method(syms[i]);
        if (!m) continue;
        if (count) jb_c(&j, ',');
        jb_c(&j, '"'); jb_esc(&j, m); jb_c(&j, '"');
        count++;
    }
    // Interpreted (nterp) frames the CFI walk can't reach, innermost-first, appended
    // after the native-resolved managed frames.
    for (int i = 0; i < nterp_n; i++) {
        if (!nterp_names[i] || !nterp_names[i][0]) continue;
        if (count) jb_c(&j, ',');
        jb_c(&j, '"'); jb_esc(&j, nterp_names[i]); jb_c(&j, '"');
        count++;
    }
    jb_c(&j, ']');
    if (count == 0 || j.err || !j.b || j.len + 1 > cap) { free(j.b); return 0; }
    memcpy(out, j.b, j.len);
    out[j.len] = '\0';
    free(j.b);
    return count;
}

// Direct-mapped fragment cache. Keyed by stack_id (a stack signature hash), so a
// collision simply overwrites the older distinct stack (LRU-ish). Bounded static
// footprint; guarded by a mutex because the snapshot-drain thread writes while
// the record-emit thread reads.
#define JC_SLOTS 8192u          // power of two
#define JC_FRAG  208            // max fragment bytes incl. NUL
struct jc_ent { uint64_t id; int used; char frag[JC_FRAG]; };
static struct jc_ent g_jc[JC_SLOTS];
static pthread_mutex_t g_jc_lock = PTHREAD_MUTEX_INITIALIZER;

void ares_jcache_put(uint64_t stack_id, const char *frag)
{
    if (!frag) return;
    size_t len = strlen(frag);
    if (len + 1 > JC_FRAG) return;          // too large to cache; record just omits
    pthread_mutex_lock(&g_jc_lock);
    struct jc_ent *e = &g_jc[stack_id & (JC_SLOTS - 1)];
    e->id = stack_id;
    e->used = 1;
    memcpy(e->frag, frag, len + 1);
    pthread_mutex_unlock(&g_jc_lock);
}

int ares_jcache_get(uint64_t stack_id, char *out, size_t cap)
{
    int found = 0;
    pthread_mutex_lock(&g_jc_lock);
    struct jc_ent *e = &g_jc[stack_id & (JC_SLOTS - 1)];
    if (e->used && e->id == stack_id) {
        size_t len = strlen(e->frag);
        if (len + 1 <= cap) {
            memcpy(out, e->frag, len + 1);
            found = 1;
        }
    }
    pthread_mutex_unlock(&g_jc_lock);
    return found;
}

void ares_jcache_reset(void)
{
    pthread_mutex_lock(&g_jc_lock);
    memset(g_jc, 0, sizeof(g_jc));
    pthread_mutex_unlock(&g_jc_lock);
}
