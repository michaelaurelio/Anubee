// SPDX-License-Identifier: GPL-2.0
// Build a Binder method-name table (binder_api_parse.h) from the running
// device's framework jars, shared by the analyzers that name Binder calls.
#ifndef __ANUBEE_BINDER_NAMES_LOAD_H
#define __ANUBEE_BINDER_NAMES_LOAD_H

#include "modules/binder_api_parse.h"

// /system/framework/framework.jar (platform AIDL stubs) plus the mainline
// modules' /apex/*/javalib/framework-*.jar. The jars stay mapped for the
// life of the process (names point into them). *njars (may be NULL) gets the
// number of jars that contributed. NULL only on allocation failure.
struct binder_names *binder_names_load_device(int *njars);

#endif /* __ANUBEE_BINDER_NAMES_LOAD_H */
