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

### Provenance carriers (`OAF-PROV-001`)

`DataProvenance` is validated as a bounded, closed structure at security
boundaries. `ProvenancedDatum<T>` carries security-relevant values together
with that metadata: canonical action data, scanner whole-text sanitization,
sanitization spans, egress/memory phase payloads, session-facing sanitized
text, and network mutations all require it. Sanitization cannot upgrade trust;
the resulting session value retains the least-trusted contributing source.

Browser observations and scanner findings retain origin, frame/page/element
identity and timestamps when available. Traces retain only this bounded
metadata and redacted evidence hashes, never carrier values, page text, secret
values, or provider credentials. See [ADR-0017](../../docs/adr/0017-provenance-carrier-contract.md).

### Session taint floor (`OAF-PROV-002`)

Calling `session.observe()` or returning text through
`session.inspectUntrustedText()` releases untrusted context and permanently
activates the session's v0.1 web-trust floor. Later proposed actions are
authorized with web instruction provenance, even if an agent transforms the
content or labels its result as application data. Internal adapter
reobservation uses `observeForAuthorization()` and does not release content.

An application can record a trusted TB1 user instruction only with
`session.authorizeActions(actions, { instructedBy: "user" })`; direct
`trust: "user"` action metadata is rejected. The claim is traceable but does
not bypass capability, origin, sink, risk, budget, or state-binding checks.
Taint does not decay on navigation, popup, retry, or quarantine release; only
creating a new session starts without a floor.

### Sink-bound secret resolution (`OAF-DATA-003`)

Core creates a `SecretResolver` only inside a session-issued, one-shot
`AuthorizedAction` execution. Before vault access it repeats the live policy,
capability, risk, intent-expiry, handle-in-operation, origin, field type,
selector, and form-action checks. Missing or mismatched metadata, stale state,
READ_ONLY/QUARANTINED sessions, and resolver reuse return no value without
calling the vault. Resolution attempts trace only handle/sink fingerprints,
outcome, and stable reason codes.

Supported v0.1 sink field types are adapter-declared bounded identifiers.
Core's `inferSecretFieldType()` derives password/text/select and standard text
input types from live tag/type/autocomplete/name/id/role metadata rather than
agent descriptions. Playwright currently materializes whole-value handles only
for fill/type/select-option. Stagehand, header, upload, file-path, and message
secret sinks remain unavailable. An application must list exact values in the
trusted task contract. A NORMAL
execution can establish the exact `(handle, origin, field type, optional
selector/form action)` sink. RESTRICTED may reuse that sink only under
`keep_approved_sinks`; `deny_all` disables it. Navigation-chain binding remains
a documented future extension because the current ActionIntent has no such
state field.

### Destination-aware egress DLP (`OAF-DATA-005`)

`EgressInspector` checks bounded ephemeral `EgressPayload` values before an
authorized action or an enforceable routed request proceeds. Registered values
match the complete v0.1 D-11 set: exact, trim/case combinations, one URL
encoding, and standard Base64. Base64URL, recursive decoding, Unicode folding,
and user regex are deliberately excluded. A match is allowed only when both the
canonical destination origin and the explicit sink or live field type are
declared by the trusted secret binding; missing metadata, cancellation, and
overflow block with stable reasons.

Raw inspected values never enter findings, plugins, network records, events, or
traces. Trace schema 1.3 records only sink, verdict, byte/match counts, and
stable reasons. Canonical actions cover URL query/fragment, typed/message/form
data, and upload metadata. Browser request bodies are inspected only through a
measured pre-effect adapter hook.

### Fixed cross-origin exfiltration rule (`OAF-DATA-006`)

The Action Guard independently classifies NAVIGATE, SUBMIT, UPLOAD, MESSAGE,
and PASTE candidates using the session taint floor, datum provenance,
registered-value matches, and opaque handles. Tainted or sensitive data sent
to a cross-origin sink blocks at fixed layer 3 unless an exact registered
value destination/sink binding applies. A general origin allowlist is not a
data binding. All handles remain inert on these action types; executor-side
handle support stays limited to exact field operations.

The rule runs before scanners, policy approval, and semantic evidence, emits
stable `untrusted_cross_origin_egress` plus applicable sink/destination/
untrusted-navigation reasons, and applies the monotonic `secret_requested`
risk signal on each rejected attempt. Same-origin or exact-bound NORMAL cases
still pass every envelope, policy, budget, risk, and state-binding check.

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

### Network Mutation Guard (`OAF-CORE-017`, `OAF-DATA-007`)

`NetworkMutation` represents a single page/tool-originated network effect
(navigation, redirect, form, fetch/XHR, headers, WebSocket, `sendBeacon`,
service worker, upload/download, popup, WebMCP) with a factual initiator
(`authorized_action | page_script | form | redirect | webmcp | service_worker |
unknown`) and bounded, redacted request metadata (headers + body hash/size,
never raw values). Per-surface capabilities are `enforced | observed_only |
unavailable`, and observation can never be promoted to enforcement.
`validateNetworkMutation` / `validateNetworkCapabilities` gate this untrusted
data before the guard; correlation to an `ActionIntent` is evidence only.
Each mutation also requires bounded source provenance and trace records retain
only that metadata.

`evaluateNetworkMutation` independently rechecks the actual source origin,
destination, scheme, private/internal-network status, risk restrictions, and
the ephemeral DLP result. Every surface marked `enforced` must supply a
complete egress inspection or the guard blocks before continuation. A proven
live `actionIntentId` is recorded as `matched` evidence but removes no guard
check; absent, different, expired, or destination-mismatched intent claims
cannot grant authority. `observed_only` and `unavailable` mutations always
produce `observe_only_gap` with `network_enforcement_unavailable`, never a
clean/continue result. The configured per-surface matrix is part of
`BrowserAdapterCapabilities` and the session-start trace.
Application-owned guard-provider transport never enters the browser adapter's
mutation event sink and is therefore outside this browser network policy.

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

`runPhase` enforces fixed Tier 0 → Tier 1 → Tier 2 barriers under one phase
deadline. A critical deterministic result skips both semantic tiers. Routing
records contain only the phase, tier, invoked/skipped status, scanner count,
and stable skip reason. For direct provider routing, `runDetectorRouter`
returns the same evidence-only results plus `blockingFailure`; callers must
deny a side effect when a configured required tier fails. Providers and
plugin scanners never receive session policy, secret, or authorization
capabilities.

Applications opt into guard-backed scanners through
`OpenAgentFenceOptions.guardScannerFactories`. Each factory runs once per
session and receives only `SessionGuardClassifier`, which routes through that
session's provider deadline and atomic guard call/token ledger. The provider
object and credentials are never exposed to a scanner, and the ordinary plugin
context does not contain this callback.

A session remembers availability failures from scanners declared
`required: true`. The semantic result remains evidence only, but the separate
deterministic session boundary denies high-impact actions with
`scanner_unavailable` until the required check succeeds. READ/SCROLL remain
available under the normal policy and risk controls.

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
