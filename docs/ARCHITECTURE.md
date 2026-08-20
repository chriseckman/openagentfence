# OpenAgentFence Architecture

**Status:** Living document. Reflects PRD v0.9
([browser-agent-firewall-prd.md](browser-agent-firewall-prd.md)) and the
accepted ADRs in [adr/](adr/README.md), plus Proposed ADR-0010 where explicitly
marked. M0 is complete; M1 is reopened for the PRD v0.9 contract backfill;
M2 is under conformance and security remediation. This document defines the
boundaries implementation must respect.

**Purpose.** The PRD says *what* OpenAgentFence must do and *why*. This
document says *how the system is divided*: trust boundaries, packages, the
domain model, lifecycles, and the execution models for scanning, policy,
secrets, provenance, and session risk. Where the PRD leaves a question open,
it is listed in [Open architectural questions](#18-open-architectural-questions)
rather than silently decided.

**Governing rule** (PRD §39, [ADR-0003](adr/0003-deterministic-authorization-is-final-boundary.md)):

> Detection informs security. Authorization enforces security.

Contents

1. [System context](#1-system-context)
2. [Trust boundaries](#2-trust-boundaries)
3. [Package boundaries](#3-package-boundaries)
4. [Core domain model](#4-core-domain-model)
5. [Lifecycle](#5-lifecycle)
6. [Scanner execution model](#6-scanner-execution-model)
7. [Policy architecture](#7-policy-architecture)
8. [Stagehand architecture](#8-stagehand-architecture)
9. [Playwright architecture](#9-playwright-architecture)
10. [Secret architecture](#10-secret-architecture)
11. [Provenance and taint model](#11-provenance-and-taint-model)
12. [Session risk model](#12-session-risk-model)
13. [Approval architecture](#13-approval-architecture)
14. [Trace and receipt architecture](#14-trace-and-receipt-architecture)
15. [Extension architecture](#15-extension-architecture)
16. [Performance architecture](#16-performance-architecture)
17. [Configuration and identity](#17-configuration-and-identity)
18. [Open architectural questions](#18-open-architectural-questions)

---

## 1. System context

```text
                Application / User
                        |
                        v  task + capabilities + policy
                +---------------+
                | Task Contract |  -> compiled into an immutable Capability Envelope
                +-------+-------+
                        |
                        v
                +---------------+      raw page state (DOM, ARIA, URL, frames,
                | Browser       | <--- screenshots, downloads, navigation events)
                | Adapter       |
                +-------+-------+
                        |  PageObservation
                        v
                +------------------+
                | Perception Guard |  PERCEPTION-phase scanners; sanitize; taint
                +-------+----------+
                        |  sanitized context + findings
                        v
                +------------------+
                | Agent / Planner  |  (application-owned; any model, any framework)
                +-------+----------+
                        |  proposed framework action
                        v
                +------------------+
                | Action Guard     |  normalize -> PRE_ACTION scanners -> policy
                +-------+----------+     -> risk aggregation -> state-bound decision
                        |  ALLOW / ALLOW_SANITIZED / REQUIRE_APPROVAL / BLOCK ...
                        v
                +------------------+
                | Revalidator      |  re-resolve target/state -> exact authorized action
                +-------+----------+
                        |
                        v
                +------------------+
                | Browser Executor |  adapter executes; secret handles resolve here
                +-------+----------+
                        |  POST_ACTION scanners; EGRESS scanners
                        v
                +---------------------------+
                | Egress / External Systems |
                +---------------------------+
```

Parallel systems, all owned by `core` and consulted from the pipeline above:

| System | Role |
|--------|------|
| **Policy Engine** | Deterministic evaluation of static configuration + task contract + runtime state into `PolicyDecision`s. |
| **Security Orchestrator** | Runs scanners per phase, enforces timeouts/cancellation, aggregates results, applies precedence. |
| **Session Risk Engine** | Accumulates risk, drives `NORMAL -> RESTRICTED -> READ_ONLY -> QUARANTINED`, enforces budgets. |
| **Provenance / Taint Engine** | Labels data with origin and trust; propagates the session taint floor; matches secret/PII values at egress. |
| **Secret Vault / Resolver** | Holds raw values behind a `VaultAdapter`; resolves opaque handles only for approved sinks, executor-side. |
| **Trace / Receipt system** | Records redacted, replayable security events; hash-linked receipts are P1. |
| **Guard Model Providers** | BYOK semantic classifiers behind `GuardModelProvider`; evidence only. |
| **Approval system** | Delivers `REQUIRE_APPROVAL` decisions to the application-registered handler; denies on timeout or when absent. |
| **Network Mutation Guard** | Independently classifies and checks action-, page-, form-, redirect-, WebMCP-, and service-worker-originated network effects; correlates with an `ActionIntent` only when proven. |

The **agent/planner is not part of OpenAgentFence.** OpenAgentFence surrounds
it: it shapes what the agent perceives (Perception Guard), gates what the
agent does (Action Guard), and controls what data may leave and persist
(Egress and Memory Guards). It never assumes the agent is honest.

---

## 2. Trust boundaries

Each boundary lists the trust of the far side, what crosses it, and what
OpenAgentFence enforces there. Boundary IDs are referenced from
[THREAT_MODEL.md](THREAT_MODEL.md).

| # | Boundary | Trust of the far side | What crosses | Enforcement at the boundary |
|---|----------|----------------------|--------------|------------------------------|
| TB1 | **Application -> OpenAgentFence** | Trusted (in scope). The application defines the task, policy, provider instance, and approval handler. A hostile application is out of scope (see [SECURITY.md](../SECURITY.md)). | Task contract, `PolicyEngine`, instantiated `GuardModelProvider`, vault registrations, approval decisions, escape-hatch calls. Provider options and credentials go from the application only to `@openagentfence/providers`, not to `core`. | Schema validation of all inputs; policy versioning; provider-option validation at the provider factory; escape-hatch use recorded in trace. |
| TB2 | **Browser / web -> OpenAgentFence** | **Untrusted.** All page content, DOM, ARIA, screenshots, URLs, downloads, frame content, page-provided tool manifests/schemas/annotations, tool outputs, and network events. | `PageObservation`, WebMCP/tool metadata and output, navigation/download/popup events, `NetworkMutation` metadata. | Perception Guard scanners; provenance labelling (`trust: web`); sanitization; size/token/time limits; schema validation; network-mutation checks where interception exists. |
| TB3 | **OpenAgentFence -> guard model** | **Untrusted; evidence only.** The provider may be compromised, malicious, unavailable, or consistently wrong and may see only bounded redacted content. | Redacted classification requests; provider transport authentication; structured classification responses. | Only bounded redacted/targeted content is sent; browser/user secrets are never sent; a provider credential is used only as transport authentication to the configured endpoint and is never classification content or telemetry; responses are schema-validated as untrusted input and can become findings only ([ADR-0003](adr/0003-deterministic-authorization-is-final-boundary.md)); cancellation, deadlines, and budgets. |
| TB4 | **Agent -> Action Guard** | **Untrusted.** The agent may be manipulated. | Proposed actions (framework-specific), model output, memory-write candidates. | Normalization to `CanonicalAction`; PRE_ACTION scanners; deterministic policy; provenance and secret checks; approval; fail-closed. |
| TB5 | **Executor -> browser** | Executor is trusted adapter code; the browser is untrusted. | Exact structured framework calls with resolved values. | Guarded execution accepts only a branded `AuthorizedAction`; the adapter re-resolves state immediately before execution and executes that exact operation; secret handles resolve here and nowhere earlier; POST_ACTION validation follows. |
| TB6 | **Browser -> network** | Untrusted destination and untrusted initiator unless proven. | Navigations, redirects, form posts, fetch/XHR, WebSocket, `sendBeacon`, service-worker traffic, WebMCP effects, uploads. | `NetworkMutationGuard`; origin/private-network policy; redirect-chain inspection; EGRESS scanners and destination-aware DLP through adapter interception hooks; action correlation never substitutes for inspection. |
| TB7 | **Vault -> allowed sink** | The vault is trusted; a sink is trusted only if explicitly bound. | Raw secret values. | Sink binding (origin, field type, optional selector/form action/nav chain); session state; never through model context, scanners, traces, or plugins. |
| TB8 | **Session -> persistent memory** | Memory is untrusted on read if web-derived. | Memory-write candidates; memory reads. | PERSISTENCE scanners; provenance retained; instruction/data separation; re-tainting on read. |
| TB9 | **Plugin -> OpenAgentFence core** | Third-party scanners/providers are least-privilege. | Scanner registration; scoped context views; results. | Manifest permissions; scoped `SecurityContext` views; no raw secrets; no arbitrary code loading; timeouts; results cannot widen capability. |

---

## 3. Package boundaries

The repository is a pnpm/Turborepo monorepo (PRD §28-29). Dependency
direction is strictly downward; `core` is the leaf.

```text
                     +----------------------+
                     |  @openagentfence/cli |
                     +----------+-----------+
                                |
      +---------------+---------+---------+------------------+
      |               |                   |                  |
+-----v-----+  +------v------+  +---------v--------+  +------v-------+
|  testing  |  |   policy    |  |     scanners     |  |  providers   |
+-----+-----+  +------+------+  +---------+--------+  +------+-------+
      |               |                   |                  |
      |     +----------------+   +--------+--------+         |
      |     |   playwright   |   |      vault      |         |
      |     +--+-------------+   +--------+--------+         |
      |        ^                          |                  |
      |  +-----+------+                   |                  |
      |  | stagehand  |                   |                  |
      |  +-----+------+                   |                  |
      |        |                          |                  |
      +--------+---------+----------------+------------------+
                         |
                  +------v------+
                  |    core     |   (no framework, no vendor SDK, no model)
                  +-------------+
```

`stagehand -> playwright` is a *permitted, optional* edge (see
[Open questions](#18-open-architectural-questions), Q3). Every other adapter
depends only on `core`.

### `@openagentfence/core`

- **Responsibilities:** all domain contracts (§4); the `OpenAgentFence`
  facade and `SecuritySession`; Security Orchestrator (scanner registry,
  phase execution, timeouts, aggregation, precedence); Perception Guard and
  Action Guard, Egress Guard, and Memory Guard pipelines; Session Risk Engine and budgets; Provenance/Taint
  Engine; secret handle codec, `SecretResolver`, and the `VaultAdapter`
  interface; `PolicyEngine` interface, `PolicyDecision`, and a
  **secure-default engine** (PRD §13.6 capability defaults) so `core` is
  safe with no policy configured — the facade accepts only a `PolicyEngine`,
  never a file path ([ADR-0008](adr/0008-policy-loading-and-facade-boundary.md)); `ApprovalHandler` interface and approval
  flow; trace writer and redaction; the `BrowserAdapter` and
  `GuardModelProvider` interfaces; the framework-neutral **in-page probe**
  (a serialisable script that collects DOM/visibility signals; adapters
  inject it); language-neutral schemas (trace, canonical action, plugin
  manifest) or their TypeScript sources.
- **Allowed dependencies:** none on Stagehand, Playwright, vendor model
  SDKs, or network clients. Small, audited utility dependencies only
  (schema validation, hashing). Every dependency added here requires
  justification ([AGENTS.md](../AGENTS.md)).
- **Forbidden:** YAML parsing/policy-file loading (belongs to `policy`);
  the concrete scanner catalog (belongs to `scanners`) beyond the minimal
  built-in checks the Action Guard must always have (secret-handle-in-action
  detection, envelope evaluation, private-network destination check);
  provider HTTP code; browser automation.
- **Public API direction:** `OpenAgentFence`, `SecuritySession`, contract
  types, `defineScanner()`, `BrowserAdapter`, `GuardModelProvider`,
  `VaultAdapter`, `PolicyEngine`, `ApprovalHandler`, trace types. Marked
  `unstable_` / `@experimental` until declared stable (no later than v0.3,
  PRD §29.6).

### `@openagentfence/policy`

- **Responsibilities:** the `openagentfence.yml` / JSON policy document
  model and its **published, versioned JSON Schema**; loading and
  validation; a deterministic evaluator implementing `PolicyEngine`;
  reusable profiles (`read-only-research`, `authenticated-read-only`,
  `form-filling`, `shopping-with-approval`, `admin-high-security`,
  `developer-local-browser`); programmatic hooks
  (`policy.on("pre_action", ...)`, P1); suppression records with
  justification; policy hashing for traces and receipts.
- **Allowed dependencies:** `core`; a YAML parser; a JSON-Schema validator.
- **Forbidden:** browser access; network; model calls; secret values.
- **Public API direction:** `loadPolicy(pathOrDocument): Promise<PolicyEngine>`,
  `validatePolicy()`, `policyProfile(name)`, `createPolicyEngine(document)`
  ([ADR-0008](adr/0008-policy-loading-and-facade-boundary.md)).

### `@openagentfence/vault`

- **Responsibilities:** the reference **in-memory `VaultAdapter`** (never
  persists to disk); registration helpers producing handles; sink-binding
  configuration types; post-MVP adapters (OS keychain, HashiCorp Vault,
  AWS Secrets Manager) as separate entry points or packages.
- **Allowed dependencies:** `core`.
- **Forbidden:** resolution *authorization* logic (that lives in `core`'s
  `SecretResolver`, so a vault implementation cannot weaken sink binding);
  logging of values; model or browser access.
- **Public API direction:** `inMemoryVault()`, `VaultAdapter`
  implementations, `SinkBinding` helpers.

### `@openagentfence/scanners`

- **Responsibilities:** the P0/P1 scanner catalog (PRD §14) as
  `SecurityScanner` implementations, grouped by phase: DOM visibility
  classifier, hidden-DOM, ARIA/DOM consistency, attribute, HTML comment,
  metadata/JSON-LD, encoded-payload normalizer and Unicode-invisible
  scanner, prompt-injection heuristics (locale-extensible rule packs),
  secret and sensitive-data scanners, URL and link-spoof scanners,
  cross-origin navigation, local-network/SSRF, task-capability,
  secret-exfiltration, form-submission, upload, download-metadata,
  memory-write; and the BYOK injection scanner (uses the
  `GuardModelProvider` *interface* only).
- **Allowed dependencies:** `core`. No provider packages, no browser
  frameworks.
- **Forbidden:** network calls except through the narrow session-owned
  `SessionGuardClassifier` callback; direct provider access; unbounded decoding;
  access to raw secrets.
- **Public API direction:** `defaultScanners()`, individual scanner
  factories with typed options, rule-pack loading.

### `@openagentfence/providers`

- **Responsibilities:** `GuardModelProvider` adapters: OpenAI-compatible
  HTTP, Anthropic, Google/Gemini, xAI, Ollama/local, custom callback, plus a
  reserved typed-unavailable OpenCode surface; the `guardProvider(name,
  options)` factory; structured-output validation; timeouts, explicit
  separately budgeted fallback, budget-accounting hooks, and redaction before
  send. P1 response caching keyed by normalized content hash + model + policy
  version is not part of the delivered P0 gate and never caches secrets. The application owns provider
  selection and options and supplies any provider credential directly to this
  package; `OpenAgentFence` receives only the instantiated provider
  ([ADR-0009](adr/0009-application-owned-provider-runtime-configuration.md)).
- **Allowed dependencies:** `core` and the built-in `fetch` transport. The P0
  implementation has no vendor SDK dependency (D-10).
- **Forbidden:** authorization logic; access to unredacted content or
  browser/user secrets; exposing its transport credential to request content,
  `core`, policy, scanners, findings, events, approvals, traces, or caches;
  persisting content or credentials.
- **Public API direction:** `guardProvider()`, per-provider factories.

### `@openagentfence/playwright`

- **Responsibilities:** `BrowserAdapter` for plain Playwright: page
  observation (URL/origin, frames, DOM snapshot via the `core` probe, ARIA
  snapshot, screenshots), event hooks (navigation, popup/new page,
  download, request routing), a **secure wrapper** around `Page` / `Locator`
  execution methods that normalizes to `CanonicalAction` and routes through
  the Action Guard, executor-side secret substitution for exact revalidated
  `fill` / `type` / `selectOption` sinks, and the `session.unsafe.rawPage()`
  escape hatch. Handle-bearing uploads and headers are rejected in v0.1.
- **Allowed dependencies:** `core`; `playwright` as a peer dependency.
- **Forbidden:** importing Stagehand; scanner logic; policy logic.
- **Public API direction:** `playwrightAdapter(context | page)`,
  `firewall.wrap(page)`.

### `@openagentfence/stagehand`

- **Responsibilities:** `BrowserAdapter` for Stagehand v4: maps `observe`
  results to `CanonicalAction[]`; `firewall.authorizeActions(candidates)`;
  a **secure wrapper** (`firewall.wrap(stagehand)`) that performs
  observe -> normalize -> authorize -> act for `act`, gates `extract`
  outputs through the Perception Guard, supports screenshot-first agents,
  and exposes the escape hatch. Isolates all Stagehand version specifics.
  With pinned Stagehand 4.0.1, deterministic page controls, forms, uploads,
  downloads, WebMCP, secret sinks, and independent network enforcement are
  unavailable and fail closed rather than falling through generic `act`.
- **Allowed dependencies:** `core`; Stagehand as a peer dependency with a
  declared range; optionally the `playwright` adapter for shared page-level
  capture (Q3).
- **Forbidden:** duplicating security logic; direct guard-model calls.
- **Public API direction:** `stagehandAdapter(stagehand)`,
  `firewall.wrap(stagehand)`, `firewall.authorizeActions()`.

### `@openagentfence/testing`

- **Responsibilities:** local fixture server for `security-corpus/`
  (no network); corpus format and loader; attack-page fixtures; benchmark
  runner (attack success, exfil success, unauthorized-action rate,
  detection recall, false-positive rate, task completion, latency, cost);
  Vitest helpers (`expectBlocked`, `expectNoRawSecretIn(trace)`); scanner
  test harness; Promptfoo example glue.
- **Allowed dependencies:** `core`, `scanners`, `policy`; `playwright`
  (peer/dev) to drive fixtures.
- **Forbidden:** shipping in production runtime paths.
- **Public API direction:** `startFixtureServer()`, `loadCorpus()`,
  `runBenchmark()`, assertion helpers.

### `@openagentfence/cli`

- **Responsibilities:** `openagentfence init | doctor | test | replay |
  explain | policy validate`. `doctor` detects common bypass patterns (P1).
- **Allowed dependencies:** `core`, `policy`, `scanners`, `testing`,
  `providers` (for `doctor` connectivity checks), `vault`.
- **Forbidden:** security logic of its own; telemetry.
- **Public API direction:** binary only; programmatic use goes through the
  packages above.

### Dependency rules

- No package may import a package above it in the diagram.
- `core` never imports any other `@openagentfence/*` package.
- Adapters never import `scanners` or `policy`; they receive configured
  instances through `OpenAgentFence`.
- Cross-package types flow *up* from `core` only.
- Any new edge that touches `core`, `vault`, or `policy` requires an ADR.

---

## 4. Core domain model

The relationships below are binding; exact TypeScript shapes are finalized in
implementation (M1 of the [implementation plan](IMPLEMENTATION_PLAN.md)) and
declared stable no later than v0.3.

```text
TaskContract --compiles to--> CapabilityEnvelope --bound to--> SecuritySession
                                                             |
   SecuritySession --owns--> RiskState, Budgets, SecurityTrace, TaintFloor
                 --emits--> events (finding, decision, riskChanged, approvalRequired)
                 --exposes--> secrets facade (register -> SecretHandle; resolveForSink: executor only)
                 --exposes--> unsafe escape hatch (every use recorded)

SecurityContext (per scan invocation)
   = { session ref, phase, task contract, capability envelope, risk state,
       observation (PERCEPTION / POST_ACTION), proposed CanonicalAction (PRE_ACTION),
       model output (MODEL_OUTPUT), memory candidate (PERSISTENCE),
       egress payload (EGRESS), provenance labels, redaction utilities,
       deadline, cancellation signal }
   -> presented to plugins as a *scoped view* per manifest permissions

TrustedIntentContext (critic-only)
   = { trusted task, CanonicalAction metadata, destination, envelope facts,
       data classifications, safe provenance labels, risk, trusted history }
   -> never contains raw page/tool content, screenshots, decoded payloads, or secrets

SecurityScanner --scan(SecurityContext)--> ScanResult --contains--> Finding[]
Finding --carries--> source, DataProvenance, RedactedEvidence, recommendedAction
Orchestrator --aggregates ScanResult[] + PolicyDecision + RiskState--> RiskAssessment
RiskAssessment.verdict --drives--> ALLOW | ALLOW_SANITIZED | WARN | RESTRICT |
                                   REQUIRE_APPROVAL | BLOCK | QUARANTINE
REQUIRE_APPROVAL --creates--> ApprovalRequest --answered by--> ApprovalDecision (app handler only)
Every step --appends--> SecurityTrace events (redacted)

CanonicalAction + observed security state --authorize--> AuthorizedAction(ActionIntent)
AuthorizedAction --adapter re-resolve/revalidate--> exact framework operation or invalidation
Browser/page event --normalizes to--> NetworkMutation --checked independently at TB6
```

| Type | Definition and key rules |
|------|---------------------------|
| **`SecurityContext`** | Immutable per-invocation input to a scanner. Contains only what the phase needs plus session references. Plugins receive a scoped view: manifest permissions select which fields are populated (`page:visible_text`, `page:hidden_text`, `page:redacted_text`, `page:screenshot`, `action:metadata`, `action:data`, `secrets:handles`). Never contains raw secret values. Carries a deadline and an `AbortSignal`. |
| **`TrustedIntentContext`** | Restricted, immutable context for an optional P1 Intent Critic. Constructed deterministically from the trusted task, `CanonicalAction`, destination, capability-envelope facts, data classifications, safe provenance metadata, session risk, and prior trusted action summaries. It cannot contain raw web/tool content, screenshots, manifests, decoded attacker payloads, or raw secrets. The P0 contract exists before the critic implementation. |
| **`SecurityScanner`** | `{ id, phases: SecurityPhase[], priority?, kind: "deterministic" \| "semantic", tier?: "tier0" \| "tier1" \| "tier2", required?, scan(ctx): Promise<ScanResult> }` (PRD §11, plus `kind`/`tier`). `kind` is required; `defineScanner` resolves an omitted tier from kind and rejects inconsistent pairs. Tier 0 is deterministic; Tier 1 is a specialized classifier; Tier 2 is an optional BYOK semantic guard. `required` records an availability requirement for later high-impact actions. Declares timeout expectations and required context permissions. |
| **`ScanResult`** | `{ scanner, verdict: allow \| warn \| sanitize \| approve \| block, severity, confidence?, findings, sanitized?, metadata? }` (PRD §11). `verdict` is a per-scanner *recommendation*. `sanitized` replaces the input for downstream consumers only when the orchestrator accepts it. |
| **`Finding`** | Reproducible evidence (PRD §12): `id, category, title, description, source{type, selector, xpath, origin, frameOrigin, boundingBox}, provenance, evidence (redacted), recommendedAction`, plus optional `severity`/`confidence` that inherit from the parent `ScanResult` when absent. Findings are the *only* channel through which semantic classifiers influence decisions. Never contain raw secrets. |
| **`RiskAssessment`** | `{ deterministic: Finding[], semantic: Finding[], provenance: Finding[], session: SessionRisk, verdict }` (PRD §15). Built by the aggregator with fixed precedence: critical deterministic block > explicit application policy > secret/data-flow block > session restriction > semantic detection > warning-only heuristics. A semantic "allow" never removes a deterministic block. |
| **`TaskContract`** | Trusted statement of intent from the application: `task` text, requested `capabilities`, secret sink bindings, origin allowances, budgets, approval configuration. Established at `session.start()`; immutable thereafter. Page content can never modify it. |
| **`CapabilityEnvelope`** | The *compiled, enforceable* result of the validated `TaskContract` constrained by secure defaults. Answers the session's maximum possible authority without a model. The separate `PolicyEngine` may narrow that baseline or deny an action during deterministic authorization. The envelope can only **shrink** during a session (policy, risk state, budgets); it widens only through a new contract or an application approval with `scope: "session"`. Neither the source policy document nor a profile object enters `core`. |
| **`CanonicalAction`** | Framework-neutral action (PRD §13.7 taxonomy: `READ SCROLL CLICK TYPE FILL NAVIGATE SUBMIT UPLOAD DOWNLOAD OPEN_TAB CLOSE_TAB COPY PASTE EXECUTE_SCRIPT AUTHENTICATE PURCHASE DELETE PUBLISH MESSAGE CHANGE_SETTING`) with `target` (element descriptor, frame, origin), `destination` (URL/origin where applicable), `data` (values, which may contain secret handles), `instructionProvenance` (where the impulse came from), `sideEffectClass` (P1: `READ_ONLY`, `REVERSIBLE`, `EXTERNAL_SIDE_EFFECT`, `FINANCIAL`, `DESTRUCTIVE`, `SECURITY_SENSITIVE`), and the exact structured framework operation. Unknown operations normalize conservatively and cannot execute through the guarded path. |
| **`ActionIntent`** | Framework-neutral authorization snapshot proposed by ADR-0010: action/intent ids, browser-context/page id, observation revision, target identity, frame/origin, destination/form action, security-relevant attributes and visibility, policy hash, timestamps/expiry, and a hash/reference for the exact structured operation. It binds a decision to inspected state; it is not itself authority. |
| **`AuthorizedAction`** | Branded result of successful deterministic authorization carrying the sanitized `CanonicalAction`, its `ActionIntent`, resolver scope, decision/trace reference, and policy hash. Only this type reaches the guarded executor. A mismatch during pre-execution revalidation invalidates it and requires reobservation and reauthorization. |
| **`NetworkMutation` / `NetworkMutationGuard`** | Framework-neutral representation and decision contract for navigations, redirects, forms, fetch/XHR, WebSockets, `sendBeacon`, service workers, uploads/downloads, popups, and WebMCP effects. Carries actual initiator, page/frame/origin/destination, bounded redacted request metadata, enforcement capability, and optional proven `actionIntentId`; lack of correlation never implies allow. |
| **`UntrustedContent`** | Typed agent-facing content wrapper containing sanitized data, provenance, content hash/observation revision, and `instructionEligible: false`. Plain sanitized strings are not a trust upgrade; adapters and memory/tool integrations retain this wrapper until the application deliberately renders data for its agent. |
| **`SecuritySession`** | One browser context = one session (PRD §13.11). Owns the envelope, risk state, budgets, trace, event stream, secrets facade, approval plumbing, and the escape hatch. Ends with `session.end()`, which flushes the trace. |
| **`DataProvenance`** | `{ trust: user \| application \| web \| tool \| memory, origin, frameOrigin, pageId, elementId, timestamp }` (PRD §13.4). Attached to observations, findings, action data, and memory. |
| **`Taint`** | Untrusted provenance that survives transformation. v0.1: a **session-level taint floor** (any model output produced after untrusted content entered model context inherits that trust) plus **exact/normalized value matching** for secrets and PII at egress. Character-level taint through LLM transformations is out of scope for v0.1 (PRD §34 Decision 8). |
| **`SecretHandle`** | Opaque token `<SECRET:name:shortid>` / `<PII:kind:shortid>` / `<CREDENTIAL:kind:shortid>`. Parsable by `core`, meaningless without the vault. Associated with `SinkBinding`s (allowed origins, field types, optional selector / form action / navigation chain). |
| **`PolicyDecision`** | Output of the Policy Engine for one question: `{ verdict, reasons: string[], matchedRules, requiredApproval?, sanitizations?, policyHash }`. Reasons are stable, machine-readable codes (e.g. `destination_not_allowed`) so decisions are explainable and testable. |
| **`ApprovalRequest` / `ApprovalDecision`** | As PRD §13.18. The request contains a *sanitized* action, findings, risk, and `expiresAt`. The decision is `{ approved, scope: once \| session, reason?, approvedBy? }`. Only the application-registered handler can answer; absence, timeout, or error means deny. |
| **`SecurityTrace`** | Ordered, redacted event log for a session: contract, observations (sanitized), findings, scan results, proposed and normalized actions, policy decisions, approvals, post-action results, budget events, escape-hatch uses, session end. JSON with a versioned schema; replayable. Receipts (P1) are hash-linked summaries of high-impact decisions. |

Two vocabularies deliberately coexist (PRD §15): scanner verdicts are
lowercase recommendations; aggregate verdicts are uppercase decisions.
Mapping: `allow -> ALLOW`, `sanitize -> ALLOW_SANITIZED`, `warn -> WARN`,
`approve -> REQUIRE_APPROVAL`, `block -> BLOCK`; `RESTRICT` and `QUARANTINE`
are session-level and have no scanner equivalent.

---

## 5. Lifecycle

```text
SESSION START
  firewall.start({ task, capabilities, secrets, budgets })
    -> validate TaskContract (schema)             [TB1]
    -> compile baseline CapabilityEnvelope (TaskContract + secure defaults)
    -> retain PolicyEngine as a separate deterministic narrowing input
    -> bind to one browser context via BrowserAdapter
    -> risk = NORMAL; budgets armed; trace opened (contract event)

LOOP (per agent step)
  PAGE OBSERVATION
    -> adapter captures PageObservation (url, origin, frames, DOM signals via
       probe, ARIA snapshot, optional screenshot)               [TB2]
    -> provenance labels attached (trust: web, origin, frameOrigin, pageId)
  PERCEPTION SCAN
    -> PERCEPTION-phase scanners (deterministic first, then semantic if
       configured and warranted); findings; sanitized representation
    -> risk engine consumes findings (may transition state)
  SANITIZED CONTEXT
    -> only the sanitized representation is offered to the agent; hidden DOM
       text is not sent to the primary model by default (PRD §16)
    -> session taint floor set if untrusted content entered model context
  AGENT REASONING (outside OpenAgentFence)
  PROPOSED ACTION
    -> from adapter (Stagehand observe result, wrapped Playwright call, or
       explicit authorizeActions())                             [TB4]
  NORMALIZATION
    -> CanonicalAction (type, target, destination, data, provenance,
       side-effect class); secret handles detected in data
  AUTHORIZATION
    -> MODEL_OUTPUT scanners (if model output available)
    -> PRE_ACTION scanners + PolicyEngine + budgets + risk state
    -> RiskAssessment via precedence -> verdict
    -> ALLOW produces branded AuthorizedAction + state-bound ActionIntent
  APPROVAL (if REQUIRE_APPROVAL)
    -> ApprovalRequest to registered handler; deny on absence/timeout/error
  PRE-EXECUTION REVALIDATION
    -> adapter re-resolves target, frame, origin, destination/form action,
       visibility, and other security-relevant attributes
    -> changed/missing/expired state invalidates authorization
    -> reobserve + fully reauthorize within budget, or fail closed
  EXECUTION
    -> adapter executes the exact structured operation carried by the
       revalidated AuthorizedAction; no fresh inference               [TB5]
    -> secret handles resolved only now, only for bound sinks         [TB7]
    -> EGRESS scanners on outbound data where interception exists     [TB6]
  NETWORK MUTATION GUARD
    -> every observable network effect is normalized independently of
       agent actions; proven action correlation is metadata, not authority
    -> origin/private-network/egress checks before continuation where
       blocking hooks exist; unsupported surfaces are reported
  POST-ACTION VALIDATION
    -> POST_ACTION scanners: unexpected redirect/new tab/download/origin
       change/privileged mutation; risk engine updated
  TRACE
    -> every step appended (redacted); events emitted
  REPEAT

PERSISTENCE GUARD (whenever the application writes to memory)
  -> PERSISTENCE scanners; provenance retained; instructions stripped or
     marked; sensitivity classified                                   [TB8]

MEMORY READ GUARD (before application-stored content enters agent context)
  -> validate item schema + contentHash; retain original provenance; wrap
     web-derived content as untrusted data; activate session taint floor [TB8]

SESSION END
  session.end() -> trace flushed; vault handles for the session invalidated;
  final risk state and budgets recorded
```

Three rules apply throughout: (1) **an action that has not passed authorization
and immediate state revalidation cannot reach the executor** except through
the recorded escape hatch; (2) **the executor performs the exact authorized
structured operation**, never a second natural-language inference; and (3)
**a session's envelope never widens** as a result of anything observed from
the browser.

---

## 6. Scanner execution model

### Phases

`PERCEPTION`, `MODEL_OUTPUT`, `PRE_ACTION`, `POST_ACTION`, `PERSISTENCE`,
`EGRESS` (PRD §10). Every scanner declares one or more phases. The
orchestrator invokes only scanners registered for the current phase.

### Ordering and priorities

Within a phase, scanners run in **priority order** (lower number first) and
in **kind order**: all `deterministic` scanners complete before any
`semantic` scanner starts. This is what makes cheap-first routing (§16)
possible: semantic tiers are skipped when a deterministic critical block
already exists. The P0 BYOK scanner independently selects bounded structural
and heuristic regions from its scoped context; prior finding objects are not
forwarded into semantic scanner context.

Detector tiers are explicit and stable:

| Tier | Role | Authority |
|------|------|-----------|
| 0 | Deterministic browser, DOM, ARIA, URL, encoding, provenance, and instruction heuristics | Evidence plus deterministic controls where specified |
| 1 | Optional specialized injection classifier behind a provider-neutral contract | Untrusted evidence only |
| 2 | Optional local/BYOK general semantic guard and P1 critics/ensembles | Untrusted evidence only |

Tier 1 and Tier 2 responses are schema-validated before conversion to findings.
They cannot grant capability, resolve secrets, modify policy, answer approval,
or lower a deterministic verdict. A compromised provider is an expected TB3
failure mode, not a trusted authority.

Deterministic scanners run **concurrently** under a single phase deadline
(they are pure over the observation); semantic scanners run with a
configurable concurrency limit (default 2) subject to budgets (Q13).

### Deterministic vs semantic

| | Deterministic | Semantic |
|---|---|---|
| Inputs | Structured observation, action, policy | Redacted, targeted text/image excerpts |
| Output role | Can produce **critical** blocks | Evidence: findings, confidence, recommended verdict |
| Failure | Fail closed for high-risk phases (`PRE_ACTION`, `EGRESS`, `PERSISTENCE` side effects) | Fail closed only if policy says the action *requires* a semantic verdict; otherwise degrade to WARN + risk increase |
| Budget | Time only | Time, call count, token spend |
| Can be sole control for a threat class? | Yes | **No** (PRD §8.4) |

### Timeouts and cancellation

Every scanner invocation receives a deadline and an `AbortSignal`. The
orchestrator enforces a per-scanner timeout and a per-phase budget. On
timeout the scanner's result is recorded as `timed_out`, never as `allow`.
Every provider request also receives an `AbortSignal`, deadline, input/output
byte or token bounds, and remaining call/token budget. These controls are part
of the `GuardModelProvider` contract, not optional adapter behavior.

### Fail-open / fail-closed

Behavior on scanner failure or timeout is policy-driven per risk class
(`defaults.scanner_failure.low_risk`, `high_risk`) with these fixed floors:

- A failed or timed-out **deterministic** scanner in `PRE_ACTION` for a
  high-impact action (any action outside `READ`/`SCROLL`, or any action
  involving a secret handle, upload, cross-origin destination, or
  side-effect class above `REVERSIBLE`) results in `BLOCK` or
  `REQUIRE_APPROVAL`, never `ALLOW`.
- A failed **semantic** scanner never blocks a low-risk read, but adds a
  `scanner_unavailable` warning and increments risk.
- **Budget exhaustion never silently disables scanning.** If scanning cannot
  continue within budget, side-effectful actions fail closed (PRD §13.17).
- Oversized page, tool-manifest, tool-output, classifier request, or provider
  response data is rejected or marked truncated/low-confidence. It is never
  silently truncated into a clean result.
- **Scanner exhaustion** (too many scanners, oversized page) is bounded by
  resource limits; when limits are hit the page is treated as
  `VISIBLE_LOW_CONFIDENCE`/unknown and risk increases; it is not treated as
  clean.

### Aggregation

`RiskAggregator` combines `ScanResult[]`, the `PolicyDecision`, budgets, and
the current risk state into a `RiskAssessment` using the fixed precedence
(§4). It records *which* rule/finding produced the final verdict so
`openagentfence explain` can render the reason chain.

### Sanitization

A scanner may return `sanitized` content. The orchestrator applies
sanitizations sequentially in priority order — each later sanitization
operates on the already-sanitized text, and where two overlap the most
restrictive wins (removal beats replacement) — records each as a trace
event, and passes the sanitized representation downstream. Sanitization can remove or replace
content; it can never *add* trust or capability. Sanitized page text keeps
its provenance.

---

## 7. Policy architecture

Authorization is layered. Secure defaults fill capabilities omitted by the
trusted task contract; after the baseline envelope is compiled, every
policy/runtime layer can only *narrow* it except for an application approval
whose scope remains within the static policy limits:

| Layer | Source | Nature | Example |
|-------|--------|--------|---------|
| 1. Task contract + secure defaults | Validated application input; defaults fill omitted capabilities | Trusted requested authority with secure fallbacks | `capabilities.downloads: true`; omitted uploads remain denied |
| 2. Capability envelope | Compiled from 1 only | Maximum session authority; shrinks only | "uploads denied; navigation same-site" |
| 3. Static policy | `PolicyEngine` created from `openagentfence.yml`, JSON, a profile, or application code | Rules already validated outside `core`; deterministic narrowing | `actions.purchase: approval`, `navigation.block_private_networks: true` |
| 4. Runtime policy | Risk state, budgets, session approvals (`scope: session`), suppressions | Dynamic; deterministic | `RESTRICTED` disables cross-origin navigation |
| 5. Semantic advisory findings | Guard models, task-alignment scanner | Evidence; advisory unless policy elevates a category | "high-confidence injection -> restricted_mode" |
| 6. Deterministic enforcement | Action Guard applying 1-4 with 5 as evidence | Final | `BLOCK: destination_not_allowed` |

Key rules:

- **Secure defaults** (PRD §13.6) apply when nothing is configured: read
  actions allowed; navigation within trusted scope; credential use
  restricted; uploads, purchases, destructive actions, external
  communication, arbitrary JavaScript, and private-network access denied.
- **Unknown action types** follow `defaults.unknown_action` (default `block`).
- The declarative policy subset is **language-neutral** and validated by a
  published JSON Schema; TypeScript callbacks (P1) extend it and are recorded
  in traces by name and hash.
- The source policy document and profile objects stay in
  `@openagentfence/policy`; `core` receives only a `PolicyEngine`. Provider
  runtime configuration is application-owned and is not policy
  ([ADR-0008](adr/0008-policy-loading-and-facade-boundary.md),
  [ADR-0009](adr/0009-application-owned-provider-runtime-configuration.md)).
- **Suppressions** are auditable, carry a justification, and are never
  accepted from page-provided content.
- The Policy Engine is pure and synchronous over an in-memory evaluation
  input; it never performs I/O. This keeps authorization under the 50 ms
  target and replayable.

---

## 8. Stagehand architecture

Stagehand v4 exposes AI primitives (`observe`, `act`, `extract`) and
deterministic page control. The adapter uses this split as the authorization
seam:

```text
stagehand.observe(instruction)          -> candidate actions (untrusted: derived from page + model)
   -> adapter.normalize(candidates)     -> CanonicalAction[] with provenance
   -> firewall.authorizeActions(...)    -> filtered/sanitized, each with a decision + trace id
   -> bind ActionIntent                 -> inspected target/page state + exact structured operation
   -> adapter re-resolve/revalidate     -> same state, or reobserve + reauthorize / fail closed
   -> stagehand.act(authorized.action)  -> exact structured execution; no new inference
   -> POST_ACTION scan
```

Wrapper behavior (`firewall.wrap(stagehand)`):

- `act(instruction)` internally performs observe -> normalize -> authorize ->
  state-bind -> re-resolve/revalidate -> exact structured act. Passing the
  original instruction to `act()` after authorizing a candidate is a security
  defect because it can infer a different operation. If Stagehand cannot expose
  or execute a single validated structured action for a path, that path is
  **disabled by the wrapper** and reported by `openagentfence doctor`.
- Handle-bearing `act` candidates remain handle-only through `observe` and are
  disabled before generic `act(Action)`. Pinned v4 can expose action arguments
  in framework paths and configured self-healing can re-enter model inference;
  neither is an approved raw-secret sink.
- `extract(...)` results pass through the Perception Guard (`PERCEPTION` on
  the source page and `MODEL_OUTPUT` on the extraction) before they are
  returned, tainted `trust: web`.
- Stagehand 4.0.1 does not expose a proven exact, non-model page-control or
  network-enforcement boundary to this adapter. Those surfaces are disabled;
  applications that require them use the independently supported Playwright
  adapter rather than treating Stagehand `act` as equivalent.
- Screenshot-first mode: the screenshot goes to the primary model; DOM/ARIA
  is analyzed by the firewall independently; hidden DOM text is not sent to
  the primary model. v0.1 does not compare the screenshot with DOM/ARIA or
  emit discrepancy findings; the envelope and Action Guard contain actions
  proposed by a fooled model. Discrepancy detection is P1/v0.2 (PRD §13.1,
  §34 Decision 5).
- Bypass resistance: raw Stagehand/Playwright handles are reachable only via
  `session.unsafe.rawPage()` (or equivalent), and each use is recorded in
  the trace with the caller's stated reason.
- Stagehand-specific behavior (version quirks, primitive shapes) is confined
  to this package; the adapter declares a v4-only public peer range describing
  versions the project claims to support and is tested against exact pinned
  versions in development/conformance tests and CI.
- WebMCP tool manifests, names, schemas, annotations, arguments, and outputs
  are untrusted TB2/TB4 content. Listing and invocation appear in the wrapper
  coverage table. Invocation is disabled until Action Guard, Network Mutation
  Guard, output scanning/provenance, and state-binding hooks are complete.

---

## 9. Playwright architecture

The Playwright adapter must be fully usable without Stagehand.

- **Observation:** `page.url()`, frame tree with per-frame origin, DOM
  signals via the `core` in-page probe (`page.evaluate` of firewall-owned
  code), accessibility snapshot, optional screenshot.
- **Wrapped execution surface:** `page.goto`, `page.click`, `locator.click`,
  `fill`, `type`, `press`, `selectOption`, `setInputFiles`, `evaluate`
  (mapped to `EXECUTE_SCRIPT`), `context.newPage`, `page.close`; downloads
  and popups via events; `route` for request-level `EGRESS` inspection and
  origin/private-network enforcement where the application enables routing.
- **Executor-side secrets:** `fill`/`type`/`selectOption` with one whole-value
  handle resolves through `SecretResolver` after live revalidation against the
  target element's origin, inferred field type, selector, and form action. A
  handle in a URL, unsupported operation, upload/file path, or unbound header
  is a block.
- **Escape hatch:** identical semantics to the Stagehand adapter.
- The adapter contains no scanner or policy logic; it converts Playwright
  events/calls into `PageObservation`/`CanonicalAction` and back.

### Network mutation architecture

The `NetworkMutationGuard` does not assume that consequential traffic starts
with `stagehand.act()` or a wrapped Playwright method. Adapters independently
normalize browser/network activity into `NetworkMutation` records:

```text
browser event/request
  -> classify initiator (authorized_action | page_script | form | redirect |
                         webmcp | service_worker | unknown)
  -> attach page/frame/origin/destination + bounded redacted metadata
  -> attach actionIntentId only when correlation is proven
  -> origin/private-network/egress evaluation
  -> continue | block | observe-only-gap
```

Capability reporting is per surface, not one `route: boolean`: navigation,
redirect, form, fetch/XHR, headers/body, WebSocket handshake/frame,
`sendBeacon`, service worker, WebMCP, upload/download, and popup are each
`enforced | observed_only | unavailable`. A full network proxy remains
deferred, but the P0 interface cannot erase or misattribute page-originated
effects. `doctor` reports the matrix for the active adapter configuration.

---

## 10. Secret architecture

```text
secret value
  -> registered with the vault (application code, executor side)     [TB1]
  -> VaultAdapter stores it; SecretResolver mints an opaque handle
  -> handle (not value) appears in model context / task contract
  -> agent proposes an action whose data contains the handle          [TB4]
  -> Action Guard: is this a permitted sink for this handle?          (SinkBinding:
       destination origin, field type, optional selector / form action / nav chain;
       session state; capability envelope; taint)                     [TB7]
  -> if authorized: adapter executor resolves the value immediately before
     the browser call and never returns it to the caller             [TB5]
  -> if not: BLOCK with reasons (secret_sink_not_allowed, ...)
```

Rules:

- Raw values never travel through `SecurityContext`, findings, traces,
  receipts, approval requests, events, semantic caches, or plugins.
- The reference vault is in-memory and never persists to disk; other vaults
  implement `VaultAdapter` and cannot bypass `SecretResolver` (authorization
  lives in `core`).
- The **secret scanner** turns detected secrets in page/tool content into
  handles before that content reaches the model, so a page cannot cause a
  raw secret to be re-emitted.
- Value matching at egress catches raw values that leaked through some other
  path. v0.1 uses the bounded D-11 set only: exact, combined trim/case
  variants, one URL encoding, and standard Base64. It does not recursively
  decode, apply Unicode folding, accept user regex, or serialize inspected
  payload values. A match requires both a trusted destination and an explicit
  sink/field-type binding; origin alone is insufficient.
- `RESTRICTED`/`READ_ONLY`/`QUARANTINED` sessions disable *new* sink
  authorizations. In `RESTRICTED`, sinks approved earlier in the session
  remain usable by default; policy may deny them
  (`secrets.restricted_mode: keep_approved_sinks | deny_all`). `READ_ONLY`
  and `QUARANTINED` deny all resolution (PRD v0.6 §13.11; Q6).

See [ADR-0005](adr/0005-executor-side-secret-handles.md).

---

## 11. Provenance and taint model

- Every observation, finding, action datum, and memory item carries
  `DataProvenance` (`trust`, `origin`, `frameOrigin`, `pageId`, `elementId`,
  `timestamp`).
- Trust levels: `user` > `application` > `tool` ≈ `memory` (depends on
  origin) > `web`. Data from a trusted origin embedded through a less
  trusted frame inherits the **lower** trust unless policy overrides (P1
  trust downgrade rule).
- **v0.1 taint semantics:**
  1. *Session taint floor:* once untrusted content has entered model context,
     all subsequent model outputs (plans, extracted values, proposed actions)
     are labelled at most `web`-trust for authorization purposes.
     Consequently `instructionProvenance` for any action after that point is
     untrusted, and rules such as "cross-origin navigation instructed by
     untrusted content" apply.
  2. *Value matching at egress:* secrets and PII registered with the vault or
     detected by scanners are matched exactly and in normalized forms
     (case, whitespace, common encodings) in outbound data.
- **v0.2:** source-to-sink data-flow graph so flows like `PRIVATE_FILE ->
  MODEL_CONTEXT -> URL_QUERY -> UNAPPROVED_ORIGIN` are blockable even when
  the text no longer resembles the source.
- Provenance is preserved through sanitization, summarization by the
  firewall, memory writes, and replay. Where OpenAgentFence cannot observe a
  transformation (inside the agent), the taint floor covers the gap.
- Provenance is itself evidence: findings cite it, and the trace stores it.

---

## 12. Session risk model

Risk is accumulated from findings and events with policy-configurable
weights (PRD §13.11), and mapped to a state machine:

```text
NORMAL -> RESTRICTED -> READ_ONLY -> QUARANTINED
```

| State | Meaning | Effect on the envelope |
|-------|---------|------------------------|
| `NORMAL` | No significant risk. | Envelope as compiled. |
| `RESTRICTED` | Likely injection or notable anomaly; task may continue with reduced capability (PRD §13.11 restricted mode). | Allowed: `READ`, `SCROLL`, same-site `NAVIGATE`, `CLICK`/`TYPE`/`FILL` on the current origin without secrets, `DOWNLOAD` if in the contract. Uploads, cross-origin navigation, external communication, and new secret sink authorizations disabled (previously approved sinks kept unless `secrets.restricted_mode: deny_all`); other side effects require approval. |
| `READ_ONLY` | Higher risk; only observation is safe. | Only `READ`, `SCROLL`, and same-site `NAVIGATE` via links; no form interaction or typing; no secret resolution; no uploads, downloads, or account changes. |
| `QUARANTINED` | Session integrity is not trusted. | All side-effecting actions blocked; observation permitted for diagnostics; the application must explicitly release or end the session. |

Default weights (profile-overridable, PRD v0.7 §13.11): hidden injection
+40, cross-origin redirect +20, secret requested +50, unrelated new tab +30.
Default thresholds: `RESTRICTED` ≥ 40, `READ_ONLY` ≥ 80, `QUARANTINED`
≥ 120. Independent of score: a high-confidence injection finding →
`RESTRICTED`; a critical finding → `QUARANTINED`.

Rules:

- Transitions are **monotonic within a session** unless an explicit policy
  (P1 risk decay/reset) restores trust; navigation never resets risk.
- Budgets (actions, duration, navigations, guard calls/tokens, downloads,
  uploads, tabs) are enforced by the same engine; exceeding one transitions
  per `budgets.on_exceeded` (`require_approval` default; `restrict`;
  `quarantine`).
- One browser context is one session; popups and new tabs inherit the state.
- State changes emit `riskChanged` and are traced with the triggering
  finding.

---

## 13. Approval architecture

- `REQUIRE_APPROVAL` produces an `ApprovalRequest` (sanitized action,
  findings, risk, `expiresAt`) delivered to the **application-registered**
  `ApprovalHandler` (P0), or P1 channels (CLI prompt, webhook/queue, debug UI).
- No handler, timeout, or handler error => **deny** (PRD §13.18, §34
  Decision 14).
- Page-derived content cannot trigger, satisfy, or influence an approval;
  the request is built from firewall-owned data only.
- `scope: "session"` widens the runtime policy for that action class for the
  remainder of the session; it never widens beyond what the static policy
  permits to be approved.
- Every request and decision is traced (and receipted, P1).

---

## 14. Trace and receipt architecture

- The trace is a versioned JSON event stream per session, redacted by
  default (secrets never; page text optionally hashed/redacted per policy).
  The header carries `schemaVersion` (semver); additive changes bump the
  minor, breaking changes the major; replay accepts the same major and
  migrates minors. Observations are self-contained: sanitized snapshot plus
  hashes of raw content, with raw retention off by default (Q14).
- Events: session start (contract, policy hash, versions), observation
  (sanitized summary + provenance), finding, scan result, proposed action,
  canonical action, policy decision, approval request/decision, execution,
  post-action result, risk change, budget event, escape-hatch use, session
  end.
- **Replay** (P1): `openagentfence replay trace.json` re-runs scanners and
  policy over recorded observations/actions without live browser side
  effects. Replay requires that observations be self-contained.
- **Receipts** (P1): hash-linked records for high-impact decisions (`action
  ID, session ID, policy hash, sanitized action, decision, timestamp, prev
  hash`); optional local signing; no remote infrastructure.
- Trace storage is local by default; retention is the application's.

---

## 15. Extension architecture

- **Scanner plugins** implement `SecurityScanner` and ship a manifest
  declaring `permissions` (`page:visible_text`, `page:hidden_text`,
  `page:redacted_text`, `page:screenshot`, `action:metadata`,
  `action:data`, `secrets:handles`) and `network` (boolean). The
  orchestrator builds a scoped `SecurityContext` view containing only
  permitted fields; raw secrets are never available to plugins.
- Plugins are loaded by explicit registration (import + `defineScanner`),
  not by name resolution from untrusted configuration; no remote code
  loading; no `eval`. Signed manifests and sandboxed execution are P1.
- Plugin results are ordinary `ScanResult`s: they can add findings, raise
  risk, or recommend blocks; they can never widen capability or bypass
  precedence.
- **Provider adapters** implement `GuardModelProvider`; they receive only
  redacted requests and must return schema-valid structured output.
- **Vault adapters**, **approval channels**, **egress hooks** (for
  Pipelock/enterprise proxies), and **file scanner adapters** (AV, DLP)
  follow the same pattern: interface in `core`, implementations in
  separate packages, least-privilege inputs.

---

## 16. Performance architecture

Cheap-first, evidence-accumulating three-tier execution:

```text
Tier 0 deterministic rules (< 100 ms median page scan target; pure functions over the observation)
  -> browser heuristics    (visibility classes, ARIA consistency, link/URL analysis)
Tier 1 specialized model   (optional narrow injection classifier; concrete adapters P1)
Tier 2 semantic guard      (optional local/BYOK model; suspicious redacted excerpts only)
  -> optional second opinion (P1 ensemble; never overrides a deterministic critical block)
```

- Targets (PRD §23): < 100 ms median deterministic scan after snapshot;
  < 50 ms median deterministic pre-action authorization; semantic calls
  avoided for most benign elements.
- The probe collects signals in one page round-trip; classification happens
  out-of-page.
- Resource limits: maximum page/tool-output bytes and agent-facing text/tokens,
  maximum nodes per observation, maximum classifier request/response
  bytes/tokens, maximum decode depth/input/output, per-tier scanner/provider
  deadlines, total guard calls/tokens, and cancellation propagation. Limit
  exhaustion cannot produce `ALLOW` for a side-effectful action whose required
  check did not complete.
- Caching: semantic decisions keyed by normalized content hash + model +
  policy version; deterministic results for unchanged observations; never
  cache resolved secrets.

---

## 17. Configuration and identity

- Default policy file: `openagentfence.yml` (JSON also accepted), validated
  against the published schema.
- Project environment variables use the `OPENAGENTFENCE_` prefix (for
  example `OPENAGENTFENCE_POLICY`, `OPENAGENTFENCE_TRACE_DIR`,
  `OPENAGENTFENCE_GUARD_PROVIDER`). Application code may of course read its
  own variables (the PRD's `GUARD_API_KEY` examples are application-owned).
- For v0.1, `openagentfence.yml` contains authorization policy only. The
  application configures a guard provider with `guardProvider(name, options)`
  and passes the instantiated `GuardModelProvider` to `OpenAgentFence`.
  Provider credentials remain confined to application setup and the provider
  adapter; they never enter policy or `core`
  ([ADR-0009](adr/0009-application-owned-provider-runtime-configuration.md)).
- Packages: `@openagentfence/*`; CLI: `openagentfence`; primary class:
  `OpenAgentFence`. See [ADR-0007](adr/0007-project-identity-and-package-namespace.md).

---

## 18. Open architectural questions

Carried forward from the PRD or surfaced while writing this document. None
of these blocks M0-M1; each row records its decision status and, where work
remains, the milestone that owns it (see
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)).

| # | Question | Source | Resolve by |
|---|----------|--------|------------|
| Q1 | **Resolved (2026-08-15).** npm scope `@openagentfence` and PyPI `openagentfence` reserved; GitHub repository is `chriseckman/openagentfence`. No trademark search is planned. Confirm the unscoped `openagentfence` npm name only if/when the meta-package (ADR-0008) is built. | PRD §34 open item 1 | Done |
| Q2 | **Deferred by decision (PRD v0.7).** Start a Rust core only if (a) Python-sidecar demand is demonstrated *and* (b) deterministic scan p50 still misses the 100 ms target on realistic pages after JS profiling. Revisit after v0.1. | PRD §34 open item 2 | Post-v0.1 |
| Q3 | **Resolved (M2, fallback path; conformance remediation open).** OAF-BROWSER-003 implements against Stagehand's abstraction sharing only `core`. Stagehand 4.0.1 is pinned for compile-time conformance and the peer range is v4-only. Playwright-page reuse plus real runtime `evaluate`/route/popup/download compatibility still requires the M2 conformance task and may not be claimed until its exact-version CI case passes. | This document §3 | M2 |
| Q4 | **Decided: fail closed; implementation incomplete.** Every Stagehand v4 execution path, including WebMCP list/invoke, agent/batch paths, deterministic page control, `act`, and `extract`, is classified in a tested coverage table. Any path with no complete pre-execution hook is disabled by default with a typed error, listed by `doctor`, and can be reached only through the recorded escape hatch or an explicit per-path opt-in documented as an enforcement gap. | PRD §16, §18.6 | M2 remediation |
| Q5 | **Resolved by [ADR-0008](adr/0008-policy-loading-and-facade-boundary.md).** The facade accepts a `PolicyEngine` (secure-default engine when omitted); `@openagentfence/policy` exports `loadPolicy(path)`; the path-string one-liner arrives later via an unscoped `openagentfence` meta-package. | PRD §3, §18.2 | Done |
| Q6 | **Resolved (PRD v0.6 §13.11).** Restricted mode disables *new* secret sink authorizations; sinks approved earlier in the session remain usable by default, and policy may deny them (`secrets.restricted_mode: keep_approved_sinks \| deny_all`). Assigned to OAF-DATA-003. | PRD §13.11, §30 | M3/M4 |
| Q7 | **Resolved (PRD v0.6 §12).** `Finding` carries optional `severity` and `confidence`; when absent they inherit from the parent `ScanResult`. Assigned to OAF-CORE-001. | PRD §11-12, §15 | M1 |
| Q8 | **Resolved (PRD v0.7 §13.11).** Defaults: hidden injection +40, cross-origin redirect +20, secret requested +50, unrelated new tab +30; `RESTRICTED` ≥ 40, `READ_ONLY` ≥ 80, `QUARANTINED` ≥ 120; high-confidence injection → `RESTRICTED` and critical finding → `QUARANTINED` regardless of score. Profile-overridable; to be tuned against the benign corpus in M8. Assigned to OAF-SEC-006. | PRD §13.11 | M3 |
| Q9 | **Resolved and expanded (PRD v0.9 §13.9).** Authorized-action egress remains enforced as documented, while the P0 `NetworkMutation` contract independently represents page/script/form/redirect/WebMCP/service-worker traffic. Routing enforcement is opt-in where required; WebSocket/frame and unobservable surfaces remain explicit gaps until proxy integration. `doctor` reports each surface as enforced, observed-only, or unavailable. | PRD §13.9 | M1 contract / M2 adapters / M4 enforcement |
| Q10 | **Resolved (PRD v0.8 §13.12).** `session.memory.guardWrite(item)` and `guardRead(item)`; storage is application-owned; provenance and content hash persist as sidecar fields. Minimum read enforcement is P0 in OAF-PROV-005 to satisfy INV-07; OAF-PROV-006 adds enhanced cross-session reinspection and policy in P1. | PRD §13.12 | M6 |
| Q11 | **Resolved (PRD v0.7 §13.11).** `RESTRICTED`: `READ`, `SCROLL`, same-site `NAVIGATE`, same-origin `CLICK`/`TYPE`/`FILL` without secrets, contract `DOWNLOAD`; rest approval/block. `READ_ONLY`: `READ`, `SCROLL`, same-site link `NAVIGATE` only; no forms, typing, or secrets. `QUARANTINED`: observation only. See §12. | PRD §13.11 | M3 |
| Q12 | **Resolved (PRD v0.6 §36 Phase 5; D-03).** OpenAI-compatible, Ollama, custom callback, Anthropic, Google/Gemini, and xAI have direct-HTTP P0 adapters. OpenCode 1.18.18 lacked a verified tool-free strict-JSON contract and is a documented typed-unavailable optional surface. | PRD §13.3, §13.16, §36 | M5 |
| Q13 | **Resolved.** Deterministic scanners run concurrently under one phase deadline; sanitizations apply sequentially by priority, later ones operating on already-sanitized text, most-restrictive-wins on overlap (removal beats replacement), each recorded in the trace; semantic scanners run with configurable concurrency (default 2). See §6. Assigned to OAF-CORE-008. | This document §6 | M1 |
| Q14 | **Resolved (schema).** Trace header carries `schemaVersion` (semver); observations are self-contained (sanitized snapshot + hashes of raw content; raw retention off by default); replay requires the same major and migrates minors. Replay itself remains P1 (OAF-REL-005). See §14. | PRD §13.14, §29.9 | M1 (schema) / M8 (replay, P1) |
| Q15 | **Resolved for transport (PRD v0.7 §13.16; A-01).** Ollama is the local-first guard-provider transport. No model is recommended and no performance claim is made until reproducible OAF-REL-001 corpus measurements exist. | PRD §34 Decision 4 | M5 transport / M8 measurement |
| Q16 | **Proposed by ADR-0010; PRD v0.9 requires the P0 outcome.** `ActionIntent` binds exact structured actions to inspected browser state; adapters immediately re-resolve/revalidate and reobserve + reauthorize on mismatch. The existing Stagehand authorize-A/execute-B defect is already prohibited by ADR-0002 and is not gated on acceptance. | PRD §13.7; ADR-0010 | Before M3 |
