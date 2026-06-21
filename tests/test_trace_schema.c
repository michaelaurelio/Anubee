// SPDX-License-Identifier: GPL-2.0
// Host unit tests for the shared trace schema's type->name table.
#include <linux/types.h>
#include "common/trace_schema.h"

#include <stdio.h>
#include <string.h>

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", msg); }   \
} while (0)

int main(void)
{
    CHECK(strcmp(trace_type_name(TRACE_CALL), "call") == 0,         "call");
    CHECK(strcmp(trace_type_name(TRACE_RETURN), "return") == 0,     "return");
    CHECK(strcmp(trace_type_name(TRACE_SYSCALL), "syscall") == 0,   "syscall");
    CHECK(strcmp(trace_type_name(TRACE_MAP), "map") == 0,           "map");
    CHECK(strcmp(trace_type_name(TRACE_UNMAP), "unmap") == 0,       "unmap");
    CHECK(strcmp(trace_type_name(TRACE_SPAWN), "spawn") == 0,       "spawn");
    CHECK(strcmp(trace_type_name(TRACE_PROC_EXIT), "proc_exit") == 0, "proc_exit");
    CHECK(strcmp(trace_type_name(TRACE_EXECVE), "execve") == 0,     "execve");
    CHECK(strcmp(trace_type_name(TRACE_PROP), "prop") == 0,         "prop");
    CHECK(strcmp(trace_type_name(TRACE_STACK), "stack") == 0,       "stack");
    CHECK(strcmp(trace_type_name(TRACE_FUNC), "func") == 0,         "func");
    CHECK(strcmp(trace_type_name(0), "unknown") == 0,              "zero->unknown");
    CHECK(strcmp(trace_type_name(999), "unknown") == 0,           "oob->unknown");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
