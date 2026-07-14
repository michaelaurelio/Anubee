// SPDX-License-Identifier: GPL-2.0
// Single-process anonymous-executable-mapping trigger for the `mod
// fileless-exec` device smoke test (scripts/device-test.sh). No installed
// app does a raw anonymous PROT_EXEC mmap as part of normal operation --
// that's the whole point of the signal -- so this needs a purpose-built
// native binary, same rationale as massdelete-detect's/exfil-burst's own
// generators. Performs exactly one mmap(MAP_ANONYMOUS|PROT_EXEC) and holds
// it open briefly; no payload content is written into the mapping --
// detection fires at mmap() time, before any content would matter (see
// design doc's "no payload-content signal" known limitation).
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    sleep(3); // give the caller time to attach the kprobe before the mmap
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return 1;
    sleep(2); // hold the mapping open briefly so the run has time to observe it
    return 0;
}
