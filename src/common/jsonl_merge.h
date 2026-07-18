// SPDX-License-Identifier: GPL-2.0
// Pure JSONL file concatenation (no libbpf/pthread deps, so it is host-testable
// — same rationale as trace/trace_args.h). Used by the `trace` coordinator
// (EPIC C5) to combine each engine's own separate `-o` output into one file at
// the literal path the caller originally passed to `-o`, so a downstream
// consumer expecting a single JSONL stream (e.g. ANUBEE-Desktop's ingest, which
// already merge-sorts every engine's records by the shared `ktime` field
// rather than by physical file position — see EPIC C3/C4) gets exactly that
// without needing to know about the per-engine suffixed files underneath.
#ifndef ANUBEE_JSONL_MERGE_H
#define ANUBEE_JSONL_MERGE_H

// Concatenate src_paths[0..n_srcs) in order into dst_path (overwritten). A
// source path that doesn't exist or can't be opened is silently skipped —
// that engine wasn't requested, or its own setup failed — not a merge error.
// Returns the number of source files actually merged, or -1 if dst_path
// couldn't be opened for writing.
int jsonl_merge(const char *dst_path, const char *const *src_paths, int n_srcs);

#endif /* ANUBEE_JSONL_MERGE_H */
