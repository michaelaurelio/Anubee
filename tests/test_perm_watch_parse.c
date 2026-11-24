// SPDX-License-Identifier: GPL-2.0
// Host unit tests for perm-watch's snapshot parsers and diff. Fixtures are
// trimmed real output from an Android 16 device (dumpsys package / appops
// get / settings / dumpsys device_policy / dumpsys role).
#include <stdio.h>
#include <string.h>
#include "modules/perm_watch_parse.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                 \
    checks++;                                                  \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); } \
} while (0)

static const char *get(const struct pw_state *s, const char *key)
{
    for (int i = 0; i < s->n; i++)
        if (!strcmp(s->f[i].key, key)) return s->f[i].val;
    return NULL;
}

static const char PKG_OUT[] =
    "    requested permissions:\r\n"
    "      android.permission.READ_SMS\r\n"
    "    install permissions:\r\n"
    "      android.permission.INTERNET: granted=true\r\n"
    "      android.permission.SYSTEM_ALERT_WINDOW: granted=true\r\n"
    "    User 0: ceDataInode=6342 installed=true hidden=false\r\n"
    "      runtime permissions:\r\n"
    "        android.permission.POST_NOTIFICATIONS: granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT]\r\n"
    "        android.permission.READ_SMS: granted=false, flags=[ USER_SET]\r\n"
    "        android.permission.RECORD_AUDIO: granted=true, flags=[ GRANTED_BY_DEFAULT]\r\n";

static const char APPOPS_OUT[] =
    "Uid mode: COARSE_LOCATION: ignore\r\n"
    "RECORD_AUDIO: foreground\r\n"
    "START_FOREGROUND: allow; time=+23m16s101ms ago; duration=+13s301ms\r\n"
    "POPUP_BLOCK: deny\r\n"
    "RECORD_AUDIO: allow; time=+1s ago\r\n";

static const char ROLE_OUT[] =
    "    roles=[\n"
    "      {\n"
    "        name=android.app.role.SMS\n"
    "        fallback_enabled=true\n"
    "        holders=com.example.mal,com.google.android.apps.messaging\n"
    "      }\n"
    "      {\n"
    "        name=android.app.role.HOME\n"
    "        holders=com.example.malware\n"
    "      }\n"
    "      {\n"
    "        name=android.app.role.DIALER\n"
    "        fallback_enabled=true\n"
    "      }\n";

static const char DP_OUT[] =
    "  Enabled Device Admins (User 0, provisioningState: 0):\n"
    "    com.example.mal/.AdminReceiver:\n"
    "      uid=10123\n"
    "    com.example.malware/.X:\n";

struct diff_log { int n; char line[16][400]; };
static void log_diff(const char *k, const char *o, const char *v, void *ctx)
{
    struct diff_log *d = ctx;
    if (d->n < 16)
        snprintf(d->line[d->n++], 400, "%s|%s|%s", k, o ? o : "-", v ? v : "-");
}

static struct pw_state A, B;

int main(void)
{
    pw_state_init(&A);
    pw_parse_package(&A, PKG_OUT);
    CHECK(get(&A, "perm:android.permission.INTERNET") != NULL, "install perm granted");
    CHECK(get(&A, "perm:android.permission.RECORD_AUDIO") != NULL, "runtime perm granted (flags ignored)");
    CHECK(get(&A, "perm:android.permission.READ_SMS") == NULL, "granted=false / requested-only not a fact");
    CHECK(A.n == 4, "exactly the 4 granted perms");

    pw_state_init(&A);
    pw_parse_appops(&A, APPOPS_OUT);
    CHECK(get(&A, "appop:COARSE_LOCATION") && !strcmp(get(&A, "appop:COARSE_LOCATION"), "ignore"),
          "'Uid mode:' prefix stripped");
    CHECK(get(&A, "appop:START_FOREGROUND") && !strcmp(get(&A, "appop:START_FOREGROUND"), "allow"),
          "time/duration suffix dropped (would churn every poll)");
    CHECK(get(&A, "appop:RECORD_AUDIO") && !strcmp(get(&A, "appop:RECORD_AUDIO"), "foreground"),
          "first occurrence keeps the plain key");
    CHECK(get(&A, "appop:RECORD_AUDIO#2") && !strcmp(get(&A, "appop:RECORD_AUDIO#2"), "allow"),
          "repeat (uid vs package scope) keyed distinctly");

    pw_state_init(&A);
    pw_parse_component_list(&A, "accessibility",
        "com.other/.S:com.example.mal/com.example.mal.Svc", "com.example.mal");
    CHECK(get(&A, "accessibility") && !strcmp(get(&A, "accessibility"), "com.example.mal/com.example.mal.Svc"),
          "own component picked from ':' list");
    pw_state_init(&A);
    pw_parse_component_list(&A, "accessibility", "com.example.malware/.S", "com.example.mal");
    CHECK(A.n == 0, "package-name prefix of another package is not a match");
    pw_parse_component_list(&A, "accessibility", "null", "com.example.mal");
    CHECK(A.n == 0, "'null' setting -> no fact");

    pw_state_init(&A);
    pw_parse_device_admin(&A, DP_OUT, "com.example.mal");
    CHECK(A.n == 1 && get(&A, "device-admin") && !strcmp(get(&A, "device-admin"), "com.example.mal/.AdminReceiver"),
          "device admin component, trailing ':' stripped, prefix-safe");

    pw_state_init(&A);
    pw_parse_roles(&A, ROLE_OUT, "com.example.mal");
    CHECK(get(&A, "role:android.app.role.SMS") != NULL, "role held (comma list)");
    CHECK(get(&A, "role:android.app.role.HOME") == NULL, "prefix-safe role holder match");
    CHECK(A.n == 1, "only held roles");

    CHECK(!strcmp(pw_category("perm:x"), "permission") && !strcmp(pw_category("appop:X#2"), "appop") &&
          !strcmp(pw_category("role:r"), "role") && !strcmp(pw_category("device-admin"), "device-admin"),
          "categories");

    // diff
    pw_state_init(&A); pw_state_init(&B);
    pw_parse_package(&A, PKG_OUT);
    pw_parse_appops(&A, "SYSTEM_ALERT_WINDOW: default\n");
    pw_parse_package(&B, PKG_OUT);
    pw_parse_appops(&B, "SYSTEM_ALERT_WINDOW: allow; time=+1s ago\n");
    pw_parse_component_list(&B, "accessibility", "com.example.mal/.Svc", "com.example.mal");
    struct diff_log d = {0};
    int nd = pw_diff(&A, &B, log_diff, &d);
    CHECK(nd == 2, "two diffs");
    int saw_appop = 0, saw_acc = 0;
    for (int i = 0; i < d.n; i++) {
        if (!strcmp(d.line[i], "appop:SYSTEM_ALERT_WINDOW|default|allow")) saw_appop = 1;
        if (!strcmp(d.line[i], "accessibility|-|com.example.mal/.Svc")) saw_acc = 1;
    }
    CHECK(saw_appop, "changed mode reported old->new");
    CHECK(saw_acc, "added special access reported");
    d.n = 0;
    nd = pw_diff(&B, &A, log_diff, &d);
    CHECK(nd == 2 && (strstr(d.line[0], "|-") || strstr(d.line[1], "|-")), "removal reported with NULL new");
    d.n = 0;
    CHECK(pw_diff(&A, &A, log_diff, &d) == 0, "identical snapshots -> no diffs");

    printf("test_perm_watch_parse: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
