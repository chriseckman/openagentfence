# ADR-0016: Application-registered browser helper boundary

- **Status:** Accepted
- **Date:** 2026-08-19
- **Related:** PRD §§13.11, 13.13; ARCHITECTURE.md adapter lifecycle; THREAT_MODEL.md INV-08, INV-10, INV-14, INV-19, INV-21

## Context

OAF-SEC-005 needs a narrow way for an application to perform a browser-side
operation without exposing arbitrary `evaluate`, script injection, dynamic
code loading, or page-defined helper behavior. Those paths cross TB1 and can
bypass deterministic action authorization, provenance, redaction, and
state-bound execution.

## Decision

Only an application may register a browser helper. A registration is immutable
for the session and contains a stable helper name, a SHA-256 hash, a bounded
structured-argument contract, and an executor-held function reference. The
canonical action and trace record only the helper name and hash; they never
contain function source or raw arguments.

The secure wrapper may invoke only an exactly registered helper through the
normal ActionIntent, authorization, one-shot execution, and state
revalidation lifecycle. Page, agent, model, plugin, and tool content cannot
create, replace, select by dynamic source, or widen a helper registration.
Raw evaluation, script tags, dynamic fetch, storage/cookie extraction, and
filesystem or extension bridges remain denied or unavailable secure surfaces.

## Options considered

- Expose generic `evaluate` behind policy. Rejected because source text cannot
  be bounded or deterministically tied to the authorized action.
- Permit page-provided helper definitions. Rejected because untrusted web
  content would influence the TB1 capability boundary.

## Consequences

- PS-008 adds the registry, exact executor path, redacted trace data, and
  regression coverage for duplicate, altered, and page-originated helpers.
- Applications must explicitly own helper code and its stable descriptor.
- This does not create a general browser scripting facility.

## Security impact

The decision preserves deterministic authorization and exact execution for
script-like effects, while preventing untrusted content from widening TB1
authority. Tests must prove one-shot execution, argument bounds, trace
redaction, and denial of arbitrary script surfaces.

## References

- `docs/browser-agent-firewall-prd.md` §§13.11, 13.13
- `docs/ARCHITECTURE.md` adapter and authorization lifecycle
- `docs/THREAT_MODEL.md` INV-08, INV-10, INV-14, INV-19, INV-21
