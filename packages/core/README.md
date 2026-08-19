# @openagentfence/core

The framework-neutral, model-neutral dependency leaf of OpenAgentFence
([ARCHITECTURE.md](../../docs/ARCHITECTURE.md) §3). It contains the domain
contracts, the capability envelope, the policy-engine interface and
secure-default engine, the risk aggregator, the scanner API and orchestrator,
the redacted trace writer, the secret-handle codec, and the `OpenAgentFence`
facade and `SecuritySession`.

**Implemented (M1, `OAF-CORE-001…014`):**

- Contracts: phases, provenance, verdicts, risk states, findings, scan results.
- `TaskContract` schema validation and `CapabilityEnvelope` compilation
  (secure defaults, shrink-only). `validateTaskContract` returns a deeply frozen
  `ValidatedTaskContract`, and `compileTaskContract` accepts only that form.
- Runtime `validateFinding` / `validateScanResult` validators with published
  JSON Schemas (`finding.schema.json`, `scan-result.schema.json`).
- `PolicyEngine` interface + secure-default engine; stable reason codes.
- `RiskAggregator` with fixed precedence (semantic can never override
  deterministic blocks).
- `SecurityScanner` / `defineScanner` / least-privilege `ScopedContextView`.
- Orchestrator with deadlines, cancellation, and fail-closed timeouts.
- `SecuritySession` / `OpenAgentFence` facade, deny-by-default approval, and the
  recorded escape hatch.
- Redacted, versioned trace writer; secret handle codec; `BrowserAdapter`,
  `GuardModelProvider`, and in-page probe contracts.
- Runtime trace validator (`validateTraceDocument` / `validateTraceEvent`) and
  probe validator (`validateProbeResult`) so untrusted trace/probe data crosses
  runtime validation before use.

### In-page probe (`OAF-CORE-014`)

The probe (`buildProbeScript`, versioned `PROBE_VERSION`) collects
*visibility/geometry signals only* — display, visibility, opacity, dimensions,
bounding box, viewport position (`inViewport`), font size, raw color and
background (contrast ratio is computed out-of-page; raw values only),
`position`/`transform`/`clipPath`/`overflow`, pseudo-element text
(`pseudoBefore`/`pseudoAfter`), attributes, `hidden`/`aria-hidden`, frame
origin, plus document-level comments, `noscript`, metadata/JSON-LD, and links.
Classification happens out-of-page in `@openagentfence/scanners`.

Aggregate resource caps (nodes, per-field text, total text bytes, comments,
metadata, links, and a time budget) are enforced inside the page and reported
as a structured `truncation` record plus the aggregate `truncated` flag. A
limit hit is never reported as a clean observation. The probe is read-only and
never mutates the page.

### Adapter conformance (`OAF-CORE-011`)

`runAdapterConformance` and `validatePageObservation` let adapter packages
prove the observation, capability, and escape-hatch contracts against their own
adapter before claiming support. Capability flags must be truthful booleans and
cannot advertise a surface the conformance behavior does not support.

Adapters subscribe with a firewall-generated `SecuritySession` id and return a
disposer; `SecuritySession.end()` calls it to prevent stale browser listeners.
Browser event identity is opaque adapter data (`pageId`, `frameId`, revision),
never page-controlled content. This lifecycle boundary is specified by
[ADR-0011](../../docs/adr/0011-adapter-session-event-lifecycle.md).

### Intent isolation (`OAF-CORE-016`)

`TrustedIntentContext` is an allowlisted, deeply frozen, branded context for
future (P1) intent criticism: trusted task, canonical action, envelope facts,
data classifications, safe provenance (user/application only), risk, and prior
trusted-action summaries. `buildTrustedIntentContext` rejects raw strings, page
observations, screenshots, manifests, arbitrary metadata, unsafe provenance,
and unknown keys. `UntrustedContent` wraps sanitized page/tool/memory text with
its original provenance, a content hash, revision/truncation metadata, and a
type-level `instructionEligible: false` that can never be set to `true`. No
semantic critic, provider call, or model behavior is implemented here.

### Network Mutation Guard contract (`OAF-CORE-017`)

`NetworkMutation` represents a single page/tool-originated network effect
(navigation, redirect, form, fetch/XHR, headers, WebSocket, `sendBeacon`,
service worker, upload/download, popup, WebMCP) with a factual initiator
(`authorized_action | page_script | form | redirect | webmcp | service_worker |
unknown`) and bounded, redacted request metadata (headers + body hash/size,
never raw values). Per-surface capabilities are `enforced | observed_only |
unavailable`, and observation can never be promoted to enforcement.
`validateNetworkMutation` / `validateNetworkCapabilities` gate this untrusted
data before the guard; correlation to an `ActionIntent` is evidence only.

### Destination boundary (`OAF-SEC-001/002`)

Core owns one canonical HTTP(S) origin/site, scheme, private-network, internal
CIDR, and redirect-hop evaluator. Capability-envelope navigation applies
allowlist/blocklist, same-origin, and same-site checks; unsupported schemes,
private/local destinations, and redirect overflow fail closed with stable
reasons. `DestinationRules` is static, bounded policy data and may only narrow
the envelope. Adapters call this evaluator only from an actual abort hook and
must report unsupported or observed-only traffic honestly.

### Detector tiers and bounded provider execution (`OAF-CORE-018`)

Scanners declare a detector tier — Tier 0 (`deterministic`), Tier 1
(specialized classifier) and Tier 2 (semantic guard) are both `semantic` and
evidence-only; `defineScanner` resolves and validates tier/kind consistency.
`GuardModelProvider.classify` returns `unknown` and is only invoked through
`runGuardProvider`, which enforces `AbortSignal`, an absolute deadline,
input/output byte and token bounds, and remaining call/token budgets, mapping
malformed, oversized, late, cancelled, throwing, and signal-ignoring providers
to typed fail-closed outcomes (`scanner_unavailable`, never `allow`). No
provider credential, option, or SDK enters core.

### State-bound authorization (`OAF-CORE-015`, ADR-0010)

`ActionIntent` is a framework-neutral snapshot binding a canonical action to
the observation identity, target, frame/origin, destination/form action,
security attributes, visibility, policy hash, and exact operation hash, with
expiry. `computeIntentFingerprint`/`compareIntentState` yield deterministic,
property-order-independent state comparison and stable mismatch codes.
Successful authorization produces an opaque branded `AuthorizedAction` through
the session-only core minting path; the minting constructor is not public.
`BrowserAdapter.executeAuthorized` accepts only that type, so a raw
`CanonicalAction` is a compile-time error and `isAuthorizedAction` rejects
forged objects at runtime. A session accepts only authorizations it issued,
and consumes them exactly once before handing them to an adapter.

### Session risk and budgets (`OAF-SEC-006/007`)

`SecuritySession` owns a monotonic `NORMAL → RESTRICTED → READ_ONLY →
QUARANTINED` risk state. The PRD-default signals are hidden injection (+40),
cross-origin redirect (+20), secret request (+50), and unrelated tab (+30),
with thresholds 40/80/120; high-confidence injection and critical findings
force restricted/quarantined state. `READ_ONLY` permits only reads, scrolling,
and a state-bound same-site link navigation (ADR-0015). `RESTRICTED` permits
only the documented low-risk actions; remaining high-impact actions require an
application approval. Quarantine blocks all guarded actions.

The session ledger atomically reserves actions, navigations, redirect hops,
guard calls/tokens, download count/bytes, upload bytes, tabs, and duration.
Exhaustion is traced and cannot allow a side effect to proceed without the
approval path; a missing handler still denies. Browser hooks that report an
effect after it has occurred are recorded as containment evidence, not claimed
as pre-effect enforcement.

### Application approvals (`OAF-SEC-008`)

High-impact approval is an application-owned, deny-by-default boundary.
Applications register an `ApprovalHandler.requestApproval()` callback; it
receives a firewall-owned projection containing the action class, normalized
origins, trusted user/application data only, classification-only findings, a
risk snapshot, and an ISO expiry. Framework `raw` operations, page/tool/model
text, finding prose, selectors, and secret values are never forwarded. Missing,
late, cancelled, throwing, or malformed handler responses deny with stable
reason codes.

`scope: "once"` applies only to the current successful authorization, which is
then session-issued and one-shot. A `scope: "session"` response creates an
in-memory grant only for that action class and destination/sink origin while the
same static policy hash and risk state remain in force. It never expands the
capability envelope, survives session end, or bypasses a later risk, budget,
policy, action, or intent change;
such changes require a fresh authorization and, when applicable, a fresh
application approval.

**Status: not yet published.** No API is stable and nothing here is
production-ready; it targets the v0.1 plan
([implementation plan](../../docs/IMPLEMENTATION_PLAN.md)).

M1 acceptance is covered by the executable conformance gate
(`packages/core/test/m1-conformance.test.ts`), which maps OAF-CORE-001…018 and
INV-01…INV-21 guarantees to named tests including adversarial regression cases
(semantic-override, raw-compiler-input, unredacted-trace, false-capability,
stale-`AuthorizedAction`, observed-only-as-enforced).
