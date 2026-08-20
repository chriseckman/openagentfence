# ADR-0017: Provenance carrier contract

- **Status:** Accepted
- **Date:** 2026-08-19
- **Related:** PRD Â§13.4; ARCHITECTURE.md Â§Â§4-6, 11, 14; THREAT_MODEL.md TB2, TB4, TB8 and INV-01, INV-05, INV-13, INV-16, INV-17

## Context

OAF-PROV-001 requires every security-relevant datum to retain source
provenance. The existing contracts require `DataProvenance` for observations,
findings, scanner context, and instruction provenance, but permit untyped
`CanonicalAction.data`, sanitized strings/spans, egress payloads, and memory
candidates. Those paths can lose origin/frame/page/element/time metadata or
mislabel data during transformation. Trace records also omit provenance.

Making provenance non-optional needs one public carrier and migration boundary;
it changes provenance semantics and public schemas, so it cannot be decided
implicitly inside PS-012.

## Decision

Adopt a bounded `ProvenancedDatum` carrier for every security-relevant value
that crosses a core trust boundary: `value` plus a validated `DataProvenance`.
The carrier is required for canonical action data, sanitized text/spans, egress
payload metadata, memory candidates, and network-mutation metadata. It is not a
recursive per-character taint model.

`DataProvenance` has a fixed, bounded shape: trust, origin, frameOrigin, pageId,
elementId, and timestamp. All adapters must attach web provenance at TB2 with
the available browser identity and timestamp; transformations preserve source
metadata and select the least-trusted input. Where an adapter cannot establish
required source context, the exposed security-relevant surface is unavailable
rather than fabricated as trusted.

Trace events retain only redacted, bounded provenance metadata, never raw
carrier values, secrets, provider credentials, page text, or payload bodies.

## Options considered

- Require recursive provenance for every scalar in arbitrary JSON. Rejected for
  v0.1: it is a data-flow graph/character-level taint system, which is deferred.
- Keep `unknown` payloads and label only their outer scanner context. Rejected
  because transformations can silently erase or replace the actual source.

## Consequences

- PS-012 migrates core contracts, JSON schemas, adapters, scanners, traces, and
  tests; its public API reports and documentation require review.
- Existing application action-data callers must supply provenance explicitly.
- PS-013, PS-018, PS-019, and PS-020 consume the carrier without redefining its
  semantics.

## Security impact

This strengthens INV-01 and INV-13 by preventing untrusted sources from being
laundered into trusted action/egress/memory data. It preserves INV-05 through
redacted trace-only metadata and INV-16 through bounded validation. Tests must
cover missing/invalid provenance, transformation preservation, attack and benign
adapter cases, trace redaction, and fail-closed unavailable source context.

## References

- `docs/browser-agent-firewall-prd.md` Â§13.4
- `docs/ARCHITECTURE.md` Â§Â§4-6, 11, 14
- `docs/THREAT_MODEL.md` TB2, TB4, TB8; INV-01, INV-05, INV-13, INV-16, INV-17
