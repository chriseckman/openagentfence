# ADR-0005: Executor-side secret handles

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §7.4, §13.5, §13.14, §26.5, §34 (Decision 7); [ARCHITECTURE.md](../ARCHITECTURE.md) § Secret architecture; [THREAT_MODEL.md](../THREAT_MODEL.md) § Attack tree: secret exfiltration

## Context

If a raw credential is present in model context, any successful injection
can direct the agent to type it into an attacker's form or URL. The most
robust mitigation is to ensure the model never possesses the raw value: it
operates on an opaque reference, and the value materializes only at an
approved sink, on the executor side, after deterministic checks.

## Decision

1. Sensitive values are replaced before model exposure with **opaque
   handles** of the form `<SECRET:name:shortid>`, `<PII:kind:shortid>`,
   `<CREDENTIAL:kind:shortid>`. Handles carry no information sufficient to
   recover the value.
2. Raw values are held by a **`VaultAdapter`** behind an executor-side
   **secret resolver** in `core`. v0.1 ships an in-memory reference vault
   that never persists to disk; OS-keychain and enterprise vault adapters
   are post-MVP.
3. **Sink-bound resolution.** A handle resolves only for an explicitly
   allowed sink (at minimum: destination origin and field type; optionally
   selector, form-action origin, navigation chain). Resolution happens in
   the adapter's executor path immediately before the browser action, never
   in model context, never in a scanner plugin.
4. **Handles are inert everywhere except the approved sink.** A handle
   appearing in a URL, a message body, an upload, a memory write, or an
   action bound for an unapproved origin is a deterministic block condition.
5. **Raw values never appear in findings, traces, receipts, approval
   requests, events, logs, or test fixtures.** Redaction is the default;
   there is no "verbose" mode that includes secrets.
6. **Restricted, read-only, and quarantined sessions** disable new secret
   sink authorizations. In `RESTRICTED`, sinks approved earlier in the
   session remain usable by default and policy may deny them
   (`secrets.restricted_mode: keep_approved_sinks | deny_all`); `READ_ONLY`
   and `QUARANTINED` deny all resolution (PRD v0.6 §13.11).
7. Semantic caches never store resolved values.

## Options considered

- **Redaction only (mask on the way out).** Rejected as the sole mechanism:
  transformed or partially disclosed values evade string matching.
- **Trusting the model to keep secrets.** Rejected: contradicts ADR-0003.

## Consequences

- Positive: a fooled agent cannot exfiltrate what it never held; secret
  handling becomes deterministic and testable.
- Negative: adapters must implement handle substitution for `fill`/`type`,
  headers, and uploads; some flows (secrets that must be transformed before
  use) require explicit executor-side helpers.
- Follow-up: define the `VaultAdapter` and `SinkBinding` contracts; add
  exfiltration fixtures that assert zero raw-secret egress.

## Security impact

Directly implements the "secret handle cannot be resolved for an unapproved
sink" and "cross-origin secret egress denied by default" invariants.
