# ADR-0013: Policy runtime state and suppression trace boundary

- **Status:** Accepted
- **Date:** 2026-08-17
- **Accepted:** 2026-08-17 by maintainer authorization
- **Related:** [ADR-0003](0003-deterministic-authorization-is-final-boundary.md),
  [ADR-0005](0005-executor-side-secret-handles.md),
  [ADR-0008](0008-policy-loading-and-facade-boundary.md), INV-01, INV-03,
  INV-05, INV-16, INV-17, INV-20

## Context

The policy engine must remain pure, synchronous, deterministic, and I/O-free,
but deterministic policy evaluation needs trusted runtime budget facts and
bounded scanner-policy evidence. Applied scanner suppressions and matched rules
also require auditable trace representation without carrying page content or
secrets.

## Decision

1. Core defines an immutable, validated `PolicyRuntimeState` owned by the
   application/firewall. It may contain only trusted runtime counters and
   deterministic scanner-policy evidence. It contains no raw page content,
   secrets, provider credentials, semantic allow output, mutable callbacks, or
   arbitrary scanner payloads.
2. The policy engine consumes this state as a read-only evaluation fact. It
   owns no counters, clocks, randomness, or mutable session state.
3. Scanner thresholds and suppressions use typed, bounded policy APIs over
   firewall-owned scanner IDs, rule IDs, and origin metadata. Suppressions can
   affect scanner findings only; they cannot suppress capability-envelope,
   private-network, secret-sink, ActionIntent, network-mutation, or other final
   deterministic controls.
4. Trace data is extended additively with policy hash, matched rules, and
   applied-suppression identifiers/justification references. It excludes raw
   findings, page content, secrets, provider configuration, and credentials.
5. Existing aggregation precedence remains fixed. Semantic output is evidence
   only and cannot grant authority or override a deterministic block.

## Consequences

- Policy evaluation remains replayable while PS-002/PS-004 can exchange trusted
  runtime facts.
- Core API/schema, policy schema/types, tests, API reports, documentation, and
  changesets must evolve together.
- Any future runtime input must be added explicitly to the validated contract;
  untrusted scanner/page/provider data has no implicit path into policy.
