# ADR-0011: Adapter session identity for observed browser events

- **Status:** Accepted
- **Date:** 2026-08-17
- **Related:** PRD §§13.9, 17; ARCHITECTURE.md §§5, 9; THREAT_MODEL.md TB2/TB5/TB6 and INV-13/16/21; OAF-BROWSER-001/016/018

## Context

`BrowserAdapter.subscribe()` requires every navigation, popup, and download
event to contain a `sessionId`, but the framework-neutral adapter contract does
not provide an adapter with a `SecuritySession` or session identifier at
construction, observation, execution, or subscription. Playwright therefore
cannot honestly emit a real identity for browser-originated events or associate
NetworkMutations with the correct firewall lifecycle.

Inventing an empty, page-derived, or adapter-global value would violate the
provenance and independent-network-boundary guarantees. This affects TB2, TB5,
and TB6, and blocks OAF-BROWSER-001/016 completion.

## Decision

Bind an immutable firewall-generated session identity when the application
attaches an adapter event subscription.
The core-owned lifecycle API must pass that identity explicitly to the adapter;
the adapter must not derive it from browser state, page URL, or page content.

The resulting event and NetworkMutation records must carry the supplied
identity, page/context/frame identity where observable, and `trust: web`
provenance. They must not gain authorization from an ActionIntent correlation.
Unsubscribing or ending a session must detach all listeners associated with that
identity.

## Options considered

- **Adapter constructor option:** rejected as the primary boundary because an
  adapter can be constructed before a session exists and may be reused.
- **Adapter-generated identity:** rejected because it is not firewall-owned and
  cannot prove the event belongs to a specific `SecuritySession`.
- **Omit event identity:** rejected because event/network data cannot be safely
  routed, traced, or bounded by a session without it.

## Consequences

- Core needs an explicit attach/detach lifecycle contract and tests for
  identity propagation, listener cleanup, and cross-session isolation.
- Playwright and Stagehand adapters need conformance updates before they claim
  event or NetworkMutation coverage.
- `BrowserAdapter.subscribe(sessionId, sink)` and `SecuritySession.end()` now
  implement the attach/detach lifecycle. PS-012 supplies the Playwright
  regression evidence; later adapters must adopt this contract before claiming
  event or NetworkMutation coverage.

## Security impact

This strengthens INV-13 by preserving firewall-visible event provenance and
INV-21 by keeping browser/network effects independent from action authority. It
also supports INV-16 through lifecycle-bounded listener cleanup. Tests must
prove that an event cannot be assigned to another session, stale listeners do
not receive events after detachment, and page-controlled content cannot choose
an identity or authorization outcome.

## References

- [ADR-0002](0002-framework-neutral-core-with-adapters.md)
- [ADR-0010](0010-state-bound-authorization-and-pre-execution-revalidation.md)
- [Architecture: lifecycle](../ARCHITECTURE.md#5-lifecycle)
- [Architecture: Playwright](../ARCHITECTURE.md#9-playwright-architecture)
- [Threat model invariants](../THREAT_MODEL.md#6-security-invariants)
