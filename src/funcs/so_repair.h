#pragma once
#include <stdint.h>

// Repair a memory-dumped SO file so that analysis tools (IDA/Ghidra/readelf)
// can parse it correctly.  Three things are fixed:
//   1. Program header p_offset fields (stale APK/disk offsets → dump-file offsets)
//   2. RELATIVE relocation slots (remove applied load bias)
//   3. Section header table (reconstructed from PT_DYNAMIC / DT_ entries)
//
// dump_base  – lowest virtual address in the dump (= min_start from dump_library_full)
// Output is written to <dump_path>.fixed; the original dump is preserved.
void repair_dumped_so(const char *dump_path, uint64_t dump_base);
