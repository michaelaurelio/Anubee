// SPDX-License-Identifier: GPL-2.0
// Shared live-event stdout printers, generalized out of funcs.c (funcs was the
// only engine with a thread-safe out/err/timestamp trio; every engine that
// prints from more than one thread — funcs' worker+drain, syscalls' worker —
// needs the same line-serialization). One process-wide lock is correct here:
// no two engines are meant to interleave mid-line either (ares trace runs
// several engines as concurrent threads in one process — see trace.c).
//
// human_detail() generalizes funcs' "         [event]   | " continuation-line
// prefix so other engines can reuse the same indented-detail-line convention
// under their own tag word (workspace/ares-output-asymmetry.md §4.4 fix).
#ifndef __ARES_COMMON_HUMAN_OUT_H
#define __ARES_COMMON_HUMAN_OUT_H

void out_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void err_print(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ts_print(const char *fmt, ...)  __attribute__((format(printf, 1, 2))); // prepends "HH:MM:SS "

// Indented continuation line under a top-level ts_print()'d event: prints
// "         [<tag>]   | " then fmt. tag is the same word used in the parent
// line's "[tag] > ..." bracket (funcs always passes "event" today).
void human_detail(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// Sticky bottom status line on stderr (the drain progress bar). Pass a rendered
// line to pin it below all other output; NULL clears it.
//
// Every printer above clears the sticky line, prints its own line, then redraws
// it - all under the one output lock, so a worker's event line can never land
// mid-bar. Inert until a line is set, so ordinary output stays byte-identical.
void human_progress_set(const char *line);

#endif /* __ARES_COMMON_HUMAN_OUT_H */
