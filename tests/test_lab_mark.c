// Host unit tests for lab_mark_format. Pure logic: label + timestamp -> JSON line.
#include "common/lab_mark.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int checks = 0;
#define CHECK(c) do { assert(c); checks++; } while (0)

int main(void)
{
	char b[256];
	int n = lab_mark_format(b, sizeof b, 123456789ULL, "grant-begin:a11y");
	CHECK(n > 0 && !strcmp(b, "{\"type\":\"lab_mark\",\"ts_ns\":123456789,\"label\":\"grant-begin:a11y\"}\n"));
	CHECK(lab_mark_format(b, sizeof b, 1, "a\"b\\c") > 0 && strstr(b, "\"label\":\"a\\\"b\\\\c\""));
	CHECK(lab_mark_format(b, sizeof b, 1, "") == -1);
	CHECK(lab_mark_format(b, 10, 1, "launch") == -1);
	printf("test_lab_mark: %d checks passed\n", checks);
	return 0;
}
