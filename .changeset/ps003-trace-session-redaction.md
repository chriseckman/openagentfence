---
"@openagentfence/core": minor
---

Close trace, session, approval, and redaction acceptance (PS-003). Add a
dependency-free runtime trace validator (`validateTraceDocument` /
`validateTraceEvent`) that enforces semver-major compatibility, lifecycle
ordering (`session_start` first, `session_end` last), per-kind data contracts,
and reproducible `EvidenceReference` shapes; every non-ALLOW decision now
carries stable reason codes plus redacted evidence references. Session-start
traces record truthful adapter capabilities, the policy hash, and schema/core
versions without provider credentials. `PolicyEngine` gains a `policyHash`
property. Public events, approval requests/decisions, escape-hatch reasons, and
returned decisions now pass through the redaction boundary, and approval
resolution denies with stable reasons for absence, timeout, error, explicit
rejection, and malformed handler results. `trace.schema.json` is enriched to
match.
