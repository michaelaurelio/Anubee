// SPDX-License-Identifier: GPL-2.0
// managed_stack_spike.h — THROWAWAY spike (env-gated ARES_MSTACK_SPIKE). Walks
// ART Thread->ManagedStack from a snapshot's tls_base to name interpreted (nterp)
// frames exactly, instead of the heuristic snapshot-scan in nterp_name.
//
// Reads-only: /proc/<pid>/mem, same class as jit_resolve. Writes nothing, attaches
// nothing — detectability firewall intact. NOT for merge until the chain resolves
// end-to-end + explicit approval. See
//   docs/superpowers/specs/2026-07-01-managed-stack-walk-spike-design.md
//   docs/superpowers/research/2026-07-02-managed-stack-walk-spike-findings.md
#ifndef ARES_COMMON_MANAGED_STACK_SPIKE_H
#define ARES_COMMON_MANAGED_STACK_SPIKE_H

struct ares_stack_snapshot;   // full definition in common/stack_snapshot.h

// Env-gated (no-op unless getenv("ARES_MSTACK_SPIKE")). Derives Thread* from
// snap->tls_base (TLS_SLOT_ART_THREAD_SELF), empirically locates managed_stack via
// the self back-pointer, walks the ManagedStack, and prints named frames to stderr.
void ares_mstack_spike(int pid, const struct ares_stack_snapshot *snap);

#endif /* ARES_COMMON_MANAGED_STACK_SPIKE_H */
