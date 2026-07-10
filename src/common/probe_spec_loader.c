// SPDX-License-Identifier: GPL-2.0
#include "common/probe_spec_loader.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int load_probe_spec_file(const char *path, custom_probe_spec_t *out, int cap,
                         int *count, void (*log)(const char *fmt, ...))
{
	FILE *f = fopen(path, "r");
	if (!f) {
		if (log) {
			log("   [err] > cannot open spec file '%s': %s\n", path, strerror(errno));
		} else {
			fprintf(stderr, "   [err] > cannot open spec file '%s': %s\n", path, strerror(errno));
		}
		return -1;
	}

	char line[512];
	while (fgets(line, sizeof(line), f) && *count < cap) {
		// Trim trailing '\n', '\r', ' ', '\t' (canonical funcs.c behavior)
		char *end = line + strlen(line) - 1;
		while (end >= line && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
			*end-- = '\0';

		// Skip blank lines and comment lines
		if (line[0] == '\0' || line[0] == '#')
			continue;

		// Parse the spec; skip malformed lines without aborting the file
		if (parse_custom_probe_spec(line, &out[*count], log) == 0)
			(*count)++;
	}

	// Warn if cap reached but more data remains
	if (*count >= cap && !feof(f)) {
		fprintf(stderr, "warning — spec cap (%d) reached; remaining lines in '%s' ignored\n", cap, path);
	}

	fclose(f);
	return 0;
}
