// SPDX-License-Identifier: GPL-2.0
// Pure snapshot parsers + diff for `anubee mod perm-watch`. See
// perm_watch_parse.h for the fact model and the shell output each parser reads.
#include <stdio.h>
#include <string.h>
#include "modules/perm_watch_parse.h"

void pw_state_init(struct pw_state *s)
{
    s->n = 0;
    s->truncated = 0;
}

static const char *pw_get(const struct pw_state *s, const char *key)
{
    for (int i = 0; i < s->n; i++)
        if (!strcmp(s->f[i].key, key))
            return s->f[i].val;
    return NULL;
}

void pw_add_fact(struct pw_state *s, const char *key, const char *val)
{
    if (s->n >= PW_FACTS_MAX) { s->truncated = 1; return; }
    snprintf(s->f[s->n].key, PW_KEY_MAX, "%s", key);
    snprintf(s->f[s->n].val, PW_VAL_MAX, "%s", val);
    s->n++;
}

// Copy the next line of *p (without its \r\n) into buf and advance *p.
// Returns 0 at end of text.
static int next_line(const char **p, char *buf, size_t bufsz)
{
    if (!*p || !**p) return 0;
    const char *e = strchr(*p, '\n');
    size_t len = e ? (size_t)(e - *p) : strlen(*p);
    while (len && (*p)[len - 1] == '\r') len--;
    if (len >= bufsz) len = bufsz - 1;
    memcpy(buf, *p, len);
    buf[len] = '\0';
    *p = e ? e + 1 : *p + strlen(*p);
    return 1;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
    return s;
}

// True if `comp` is a component ("pkg/cls") of exactly `pkg` -- a plain prefix
// test would let com.example.mal match com.example.malware.
static int comp_is_pkg(const char *comp, const char *pkg)
{
    size_t n = strlen(pkg);
    return n && !strncmp(comp, pkg, n) && comp[n] == '/';
}

void pw_parse_package(struct pw_state *s, const char *text)
{
    char line[512];
    while (next_line(&text, line, sizeof line)) {
        char *t = trim(line);
        char *g = strstr(t, ": granted=true");
        if (!g || g == t) continue;
        *g = '\0';
        if (strchr(t, ' ')) continue;   // permission names have no spaces
        char key[PW_KEY_MAX];
        snprintf(key, sizeof key, "perm:%s", t);
        if (!pw_get(s, key))            // multi-user output repeats runtime perms
            pw_add_fact(s, key, "granted");
    }
}

void pw_parse_appops(struct pw_state *s, const char *text)
{
    char line[512];
    while (next_line(&text, line, sizeof line)) {
        char *t = trim(line);
        if (!strncmp(t, "Uid mode:", 9)) t = trim(t + 9);
        char *c = strstr(t, ": ");
        if (!c || c == t) continue;
        *c = '\0';
        char *mode = c + 2;
        char *semi = strchr(mode, ';');
        if (semi) *semi = '\0';
        mode = trim(mode);
        if (strchr(t, ' ') || !*mode) continue;
        // The uid-scope block and the package-scope block can name the same
        // op; output order is stable, so the Nth repeat gets a stable "#N".
        char key[PW_KEY_MAX];
        snprintf(key, sizeof key, "appop:%s", t);
        for (int k = 2; pw_get(s, key) && k < 10; k++)
            snprintf(key, sizeof key, "appop:%s#%d", t, k);
        if (!pw_get(s, key))
            pw_add_fact(s, key, mode);
    }
}

void pw_parse_component_list(struct pw_state *s, const char *kind,
                             const char *setting, const char *pkg)
{
    char buf[4096];
    snprintf(buf, sizeof buf, "%s", setting ? setting : "");
    char *save = NULL;
    for (char *tok = strtok_r(buf, ":\r\n", &save); tok; tok = strtok_r(NULL, ":\r\n", &save)) {
        tok = trim(tok);
        if (comp_is_pkg(tok, pkg) && !pw_get(s, kind))
            pw_add_fact(s, kind, tok);
    }
}

void pw_parse_device_admin(struct pw_state *s, const char *text, const char *pkg)
{
    char line[512];
    while (next_line(&text, line, sizeof line)) {
        char *t = trim(line);
        size_t n = strlen(t);
        if (n && t[n - 1] == ':') t[n - 1] = '\0';
        if (comp_is_pkg(t, pkg) && !strchr(t, ' ') && !pw_get(s, "device-admin"))
            pw_add_fact(s, "device-admin", t);
    }
}

void pw_parse_roles(struct pw_state *s, const char *text, const char *pkg)
{
    char line[1024], role[128] = "";
    while (next_line(&text, line, sizeof line)) {
        char *t = trim(line);
        if (!strncmp(t, "name=", 5)) {
            snprintf(role, sizeof role, "%s", t + 5);
            continue;
        }
        if (strncmp(t, "holders=", 8) || !role[0]) continue;
        char *save = NULL;
        for (char *h = strtok_r(t + 8, ", ", &save); h; h = strtok_r(NULL, ", ", &save)) {
            if (!strcmp(h, pkg)) {
                char key[PW_KEY_MAX];
                snprintf(key, sizeof key, "role:%s", role);
                if (!pw_get(s, key))
                    pw_add_fact(s, key, "held");
                break;
            }
        }
    }
}

int pw_diff(const struct pw_state *a, const struct pw_state *b,
            pw_diff_cb cb, void *ctx)
{
    int n = 0;
    for (int i = 0; i < b->n; i++) {
        const char *old = pw_get(a, b->f[i].key);
        if (!old || strcmp(old, b->f[i].val)) {
            if (cb) cb(b->f[i].key, old, b->f[i].val, ctx);
            n++;
        }
    }
    for (int i = 0; i < a->n; i++) {
        if (!pw_get(b, a->f[i].key)) {
            if (cb) cb(a->f[i].key, a->f[i].val, NULL, ctx);
            n++;
        }
    }
    return n;
}

const char *pw_category(const char *key)
{
    if (!strncmp(key, "perm:", 5))  return "permission";
    if (!strncmp(key, "appop:", 6)) return "appop";
    if (!strncmp(key, "role:", 5))  return "role";
    return key;
}
