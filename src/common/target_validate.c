// SPDX-License-Identifier: GPL-2.0
#include "common/target_validate.h"

error_t validate_pid_or_package(struct argp_state *state, int n, const char *pkg)
{
    int has_pid = (n > 0);
    int has_pkg = (pkg && pkg[0] != '\0');

    if (has_pid != has_pkg)
        return 0;  // exactly one given, valid

    argp_error(state, "specify exactly one of -p or -P");
    return EINVAL;
}

error_t validate_have_selector(struct argp_state *state, int nsel, const char *hint)
{
    if (nsel > 0)
        return 0;

    argp_error(state, "no probe targets given (%s)", hint);
    return EINVAL;
}
