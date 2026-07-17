// SPDX-License-Identifier: GPL-2.0
// Pure managed-frame chain builder + bounded stack_id cache. No libbpf/symbolizer
// deps so the host test links it directly. The impure resolver anubee_managed_chain
// and anubee_emit_cfi_stack_json live in symbolize.c (they need sym_resolve/CFI).
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
    // kind-classifier precedence in anubee_emit_cfi_stack_json (jni-trampoline first).
    if (strstr(sym, "art_jni_trampoline")) return NULL;
    if (!strstr(sym, ".oat!") && !strstr(sym, ".odex!") && !strstr(sym, ".vdex!"))
        return NULL;
    const char *bang = strrchr(sym, '!');
    return bang ? bang + 1 : NULL;
}

// ART interpreter entrypoints — a Java method is being interpreted here and has
// no native frame of its own. Shared by syscalls.c and symbolize.c.
int anubee_is_interp_frame(const char *sym)
{
    return sym && (strstr(sym, "ToInterpreterBridge") ||
                   strstr(sym, "nterp_helper")         ||
                   strstr(sym, "ExecuteNterpImpl")     ||
                   strstr(sym, "ExecuteSwitchImpl")    ||
                   strstr(sym, "artInterpreterToCompiledCodeBridge"));
}

int anubee_managed_chain_build(const char *const *syms, int n,
                             const char *const *nterp_names, int nterp_n,
                             char *out, size_t cap)
{
    // Collect method names innermost-first: native-resolved managed frames (module
    // prefix stripped), then the interpreted (nterp) chain the CFI walk can't reach.
    const char *m[128];
    const int MAXM = (int)(sizeof m / sizeof m[0]);
    int total = 0;
    for (int i = 0; i < n && total < MAXM; i++) {
        const char *mm = managed_method(syms[i]);
        if (mm) m[total++] = mm;
    }
    for (int i = 0; i < nterp_n && total < MAXM; i++)
        if (nterp_names[i] && nterp_names[i][0]) m[total++] = nterp_names[i];
    if (total == 0) return 0;

    // Emit as many frames as fit `cap`. On overflow, keep the innermost frames and
    // append a "..." marker rather than dropping the whole chain - a truncated
    // java_stack must never be mistaken for a complete one (real Kotlin/Compose
    // names make chains routinely exceed the cache fragment). Innermost-first, so
    // truncation drops the least-relevant outer callers.
    struct jbuf j = {0};
    int emitted = 0, truncated = 0;
    jb_c(&j, '[');
    for (int i = 0; i < total; i++) {
        size_t save = j.len;
        if (emitted) jb_c(&j, ',');
        jb_c(&j, '"'); jb_esc(&j, m[i]); jb_c(&j, '"');
        // Reserve room for the close ']' + NUL (2); while frames remain after this
        // one, also reserve a trailing ',"..."' (6) so a later overflow can mark.
        size_t reserve = (i + 1 < total) ? 6 + 2 : 2;
        if (j.err || j.len + reserve > cap) { j.len = save; truncated = 1; break; }
        emitted++;
    }
    if (emitted == 0) { free(j.b); return 0; }   // not even one frame fit: omit
    if (truncated) jb_s(&j, ",\"...\"");
    jb_c(&j, ']');
    if (j.err || !j.b || j.len + 1 > cap) { free(j.b); return 0; }
    memcpy(out, j.b, j.len);
    out[j.len] = '\0';
    free(j.b);
    return emitted;
}

// Direct-mapped fragment cache. Keyed by stack_id (a stack signature hash), so a
// collision simply overwrites the older distinct stack (LRU-ish). Bounded static
// footprint; guarded by a mutex because the snapshot-drain thread writes while
// the record-emit thread reads.
#define JC_SLOTS 8192u          // power of two
#define JC_FRAG  ANUBEE_JCACHE_FRAG   // max fragment bytes incl. NUL (see managed_frame.h)
struct jc_ent { uint64_t id; int used; char frag[JC_FRAG]; };
static struct jc_ent g_jc[JC_SLOTS];
static pthread_mutex_t g_jc_lock = PTHREAD_MUTEX_INITIALIZER;

void anubee_jcache_put(uint64_t stack_id, const char *frag)
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

int anubee_jcache_get(uint64_t stack_id, char *out, size_t cap)
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

void anubee_jcache_reset(void)
{
    pthread_mutex_lock(&g_jc_lock);
    memset(g_jc, 0, sizeof(g_jc));
    pthread_mutex_unlock(&g_jc_lock);
}
