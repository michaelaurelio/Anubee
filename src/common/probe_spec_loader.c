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
	int lineno = 0;
	while (fgets(line, sizeof(line), f) && *count < cap) {
		lineno++;

		// Trim trailing '\n', '\r', ' ', '\t' (canonical funcs.c behavior)
		char *end = line + strlen(line) - 1;
		while (end >= line && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
			*end-- = '\0';

		// Trim leading whitespace too, so an indented comment or spec line
		// is recognized as such instead of being handed to the parser as-is.
		char *start = line;
		while (*start == ' ' || *start == '\t')
			start++;

		// Skip blank lines and comment lines
		if (start[0] == '\0' || start[0] == '#')
			continue;

		// Parse the spec; a malformed line aborts the whole file (rather
		// than being silently skipped) so a typo in a shared spec file is
		// never just dropped without the caller noticing.
		if (parse_custom_probe_spec(start, &out[*count], log) == 0) {
			(*count)++;
		} else {
			if (log) {
				log("   [err] > spec file '%s' line %d: rejecting spec\n", path, lineno);
			} else {
				fprintf(stderr, "   [err] > spec file '%s' line %d: rejecting spec\n", path, lineno);
			}
			fclose(f);
			return -1;
		}
	}

	// Warn if cap reached but more data remains
	if (*count >= cap && !feof(f)) {
		fprintf(stderr, "warning — spec cap (%d) reached; remaining lines in '%s' ignored\n", cap, path);
	}

	fclose(f);
	return 0;
}
