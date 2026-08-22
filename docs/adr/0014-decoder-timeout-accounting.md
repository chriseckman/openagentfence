# ADR-0014: Decoder timeout accounting

- **Status:** Accepted
- **Date:** 2026-08-18
- **Accepted:** 2026-08-18 by maintainer authorization
- **Related:** [ARCHITECTURE.md](../ARCHITECTURE.md) §6, [THREAT_MODEL.md](../THREAT_MODEL.md) INV-16, [ADR-0003](0003-deterministic-authorization-is-final-boundary.md)

## Context

Encoded-payload normalization is synchronously bounded to at most eight linear
decodes under fixed input and output byte caps. Its former in-loop wall-clock
check treated operating-system or Turbo-worker descheduling as decoder work.
That made a nine-layer payload nondeterministically return
`deadline_exceeded` before it could return the required structural
`depth_exhausted` refusal.

The firewall already enforces scanner wall-clock cancellation at the async
boundary through `runWithDeadline`, using a timer and `AbortSignal`. The local
decoder limit is defense in depth against pathological single-step CPU work,
not the denial-of-service backstop for bounded input.

## Decision

1. `decodeIterative()` measures its existing 20 ms local budget with
   `process.cpuUsage()` user plus system CPU deltas, not elapsed wall time.
2. The existing input-byte, output-byte, and maximum-depth limits remain
   unchanged. A decoder that consumes its local CPU budget returns the
   fail-closed `deadline_exceeded` reason.
3. A value that reaches the configured structural depth and remains decodable
   returns the deterministic fail-closed `depth_exhausted` reason. This is a
   structural refusal, distinct from the resource refusal above.
4. `runWithDeadline` remains the unchanged outer wall-clock cancellation and
   `AbortSignal` control for scanner invocations. This decision removes no
   end-to-end scanner timeout.
5. No trace-schema change is needed: the encoded-payload scanner already
   carries either bounded refusal reason in its finding identifier and
   description.

## Consequences

- Parallel worker descheduling no longer consumes the local decoder CPU
  budget, so depth-limit outcomes are reproducible.
- Node reports process-wide CPU usage. Concurrent worker CPU can therefore
  contribute to a local delta. With no I/O or asynchronous work inside the
  bounded eight-step loop, a normal decode consumes microseconds; the residual
  false-refusal risk is accepted and is covered by repeated parallel root
  validation. It remains fail-closed if encountered.
- Regression coverage uses a synthetic CPU clock to verify both refusal
  reasons deterministically, while core timeout tests continue to cover the
  outer wall-clock cancellation contract.

## Security impact

INV-16 remains enforced by byte, depth, CPU, and outer cancellation bounds.
No decoder failure becomes clean content or an allow decision. The separate
stable reason codes preserve INV-17 explainability.
