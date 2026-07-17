// SPDX-License-Identifier: GPL-2.0
// capdump - print the firewall loudness table (src/common/capabilities.c) as
// `name\t0|1` rows so the build-time firewall gate reads loud/quiet truth
// straight from the compiled table, never re-encoding it. Host tool only.
#include "common/capabilities.h"

#include <stdio.h>

int main(void)
{
    int n = 0;
    const struct anubee_bpf_object *objs = anubee_bpf_objects(&n);
    for (int i = 0; i < n; i++)
        printf("%s\t%d\n", objs[i].name, objs[i].writes_target_memory ? 1 : 0);
    return 0;
}
