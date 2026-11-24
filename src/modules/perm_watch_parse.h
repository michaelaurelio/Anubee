// SPDX-License-Identifier: GPL-2.0
// Pure parsing + diffing for `anubee mod perm-watch` (no device, host-tested
// in tests/test_perm_watch_parse.c). A snapshot of one package's permission
// state is a set of key=value facts, built from the text the platform shell
// tools print:
//   perm:<name>=granted       dumpsys package <pkg> (install + runtime, granted=true)
//   appop:<OP>=<mode>         appops get <pkg> (mode only; ";time=..." dropped)
//   accessibility=<component> settings get secure enabled_accessibility_services
//   notification-listener=<component>  ... enabled_notification_listeners
//   device-admin=<component>  dumpsys device_policy
//   role:<role>=held          dumpsys role
// Two snapshots diff into added / removed / changed facts.
#ifndef __ANUBEE_PERM_WATCH_PARSE_H
#define __ANUBEE_PERM_WATCH_PARSE_H

#define PW_KEY_MAX   160
#define PW_VAL_MAX   160
#define PW_FACTS_MAX 1024

struct pw_fact { char key[PW_KEY_MAX]; char val[PW_VAL_MAX]; };
struct pw_state { int n; int truncated; struct pw_fact f[PW_FACTS_MAX]; };

void pw_state_init(struct pw_state *s);
// Add one fact (sets s->truncated instead when full).
void pw_add_fact(struct pw_state *s, const char *key, const char *val);
void pw_parse_package(struct pw_state *s, const char *dumpsys_package);
void pw_parse_appops(struct pw_state *s, const char *appops_get);
// `kind` is the fact key; `setting` a ':'-separated component list.
void pw_parse_component_list(struct pw_state *s, const char *kind,
                             const char *setting, const char *pkg);
void pw_parse_device_admin(struct pw_state *s, const char *dumpsys_dp, const char *pkg);
void pw_parse_roles(struct pw_state *s, const char *dumpsys_role, const char *pkg);

// Calls cb once per difference from `a` (old) to `b` (new). old_val is NULL for
// an added fact, new_val NULL for a removed one. Returns the number of diffs.
typedef void (*pw_diff_cb)(const char *key, const char *old_val,
                           const char *new_val, void *ctx);
int pw_diff(const struct pw_state *a, const struct pw_state *b,
            pw_diff_cb cb, void *ctx);

// Category of a fact key: "permission", "appop", "role", or the key itself
// for special access ("accessibility", "notification-listener", "device-admin").
const char *pw_category(const char *key);

#endif /* __ANUBEE_PERM_WATCH_PARSE_H */
