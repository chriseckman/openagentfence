# AGENTS.md — Development contract for autonomous coding agents

This file is the binding contract for any autonomous or semi-autonomous
coding agent working in the OpenAgentFence repository. It is deliberately
short; the documents it points to carry the detail. Read it at the start of
every session.

## Project identity

```text
Product:        OpenAgentFence
Repository:     https://github.com/chriseckman/openagentfence
npm scope:      @openagentfence/*
CLI:            openagentfence
Primary class:  OpenAgentFence
Config file:    openagentfence.yml
Env prefix:     OPENAGENTFENCE_
License:        Apache-2.0  (Copyright 2026 Christopher Eckman)
```

"AgentFence" was an early working name. If you encounter it in older text
as the name of this project, the identity above wins
([ADR-0007](docs/adr/0007-project-identity-and-package-namespace.md)). Do
not introduce it in code, package names, config keys, or docs.

## Source-of-truth order

When documents disagree, higher entries win. If two *substantive* documents
conflict on architecture or security, **do not silently choose** — stop,
state the conflict in your output, and propose a resolution (usually an ADR).

```text
1. SECURITY.md and the security invariants in docs/THREAT_MODEL.md §6
2. docs/browser-agent-firewall-prd.md   (the PRD)
3. docs/ARCHITECTURE.md
4. docs/THREAT_MODEL.md                 (remaining sections)
5. Accepted ADRs in docs/adr/
6. docs/IMPLEMENTATION_PLAN.md
7. The current task / issue
```

The identity block above overrides only *legacy naming* in older text; it
never overrides technical decisions.

## Mandatory rules

Security boundaries

- Read the relevant sections of `docs/ARCHITECTURE.md` and
  `docs/THREAT_MODEL.md` before changing security-sensitive code (anything
  in `core`, `policy`, `vault`, scanners, adapters' execution paths,
  decoders, trace/redaction).
- Never weaken a deterministic security boundary to improve task completion,
  benchmark numbers, or developer convenience.
- Never make semantic/LLM classification the sole authorization mechanism
  for a critical action. Guard-model output is evidence
  ([ADR-0003](docs/adr/0003-deterministic-authorization-is-final-boundary.md)).
- Do not solve a deterministic security question with an LLM when trusted
  state, capabilities, origin, provenance, sink binding, action type, or a
  reproducible comparison can decide it. Classifiers, guard models, critics,
  and ensembles are untrusted evidence: schema-validate their output, and
  never let it grant capabilities, resolve secrets, modify policy, answer an
  approval, or override a deterministic critical block (INV-20).
- An adapter must execute the exact structured action that passed
  authorization or fail closed. It must never authorize candidate A and then
  ask a model to infer an action B from natural language. State-bound
  pre-execution revalidation is specified by Proposed ADR-0010 and must not be
  claimed until that ADR is accepted and the adapter passes INV-19 tests.
- Never expose raw secrets to guard models, logs, traces, findings, events,
  approval requests, or plugins. Secrets are handles; values resolve only
  executor-side for bound sinks ([ADR-0005](docs/adr/0005-executor-side-secret-handles.md)).
- Treat page content, DOM, ARIA, screenshots, files, tool output, URLs, and
  memory derived from the web as **untrusted**. Untrusted input can never
  widen the capability envelope, bind a sink, or satisfy an approval.
- Preserve provenance wherever security-relevant data is transformed.
- Security-sensitive failures follow the documented fail-closed behavior
  (timeouts, budget exhaustion, missing approval handler → deny for
  high-risk actions). Never "temporarily" fail open.
- Every vulnerability fix ships with a regression test or corpus fixture.

Scope and architecture

- Never broaden scope merely because an implementation would be convenient.
  Do the task; note adjacent work in your report.
- Stagehand is an adapter, **not** a dependency of `@openagentfence/core`.
  Playwright support must remain possible independently of Stagehand
  ([ADR-0002](docs/adr/0002-framework-neutral-core-with-adapters.md)).
- Provider-specific model code belongs behind `GuardModelProvider` in
  `@openagentfence/providers`; `core` bundles no model and no vendor SDK
  ([ADR-0004](docs/adr/0004-local-first-byok-semantic-classification.md)).
  Provider runtime settings and credentials are application-owned; policy is
  provider-neutral, and `core` receives only an instantiated provider
  ([ADR-0009](docs/adr/0009-application-owned-provider-runtime-configuration.md)).
- Do not introduce mandatory telemetry, analytics, accounts, or cloud
  dependencies. Features that call out to the network must be opt-in and
  documented as such.
- Respect package dependency direction (`docs/ARCHITECTURE.md` §3): `core`
  is the leaf; adapters never import `scanners` or `policy`.
- Do not bypass OpenAgentFence wrappers in integration code except through
  the explicitly documented `unsafe` escape hatch, which must be recorded in
  the trace.
- Deprioritized/deferred features (visual guard model, screenshot/DOM
  semantic matching, data-flow graph, signed receipts, proxy, document
  parsing, Python SDK) stay out of the v0.1 critical path.

Dependencies and provenance

- **No copying, porting, or translating from Agent Browser Shield**
  (PolyForm Shield). It is a design reference only
  ([ADR-0006](docs/adr/0006-clean-room-implementation-policy.md)). Do not
  fetch or read its source to implement scanner internals.
- LLM Guard is MIT but archived: design reference, not a runtime dependency.
- Avoid archived or unmaintained dependencies for security-critical
  functionality unless explicitly justified in the PR.
- Any dependency added to a security-critical path (`core`, `policy`,
  `vault`, decoders, adapters' executor paths) requires written
  justification in the PR and, for `core`/`policy`/`vault`, an ADR.

Testing hygiene

- No secrets in test fixtures — synthetic values only, using the handle
  format where a secret is meant.
- No network access in tests; use the local fixture server.
- Do not delete or weaken existing security fixtures to make a change pass.

## Repository layout (planned; PRD §28)

Nothing under `packages/` exists until M0 lands. Put new code where the
plan says it belongs; do not create parallel structures.

```text
packages/core        contracts, orchestrator, guards, risk, taint, secret resolver, trace, probe
packages/policy      openagentfence.yml schema, loader, evaluator, profiles
packages/vault       in-memory reference vault, VaultAdapter implementations
packages/scanners    P0/P1 scanner catalog (deterministic + BYOK injection scanner)
packages/providers   GuardModelProvider adapters and guardProvider() factory
packages/playwright  Playwright adapter and secure wrapper
packages/stagehand   Stagehand adapter and secure wrapper
packages/testing     fixture server, corpus loader, benchmark runner, assertions
packages/cli         openagentfence init | doctor | test | replay | explain | policy validate
security-corpus/     attack and benign fixtures (hidden-dom, aria, encoding, visual,
                     exfiltration, navigation, memory)
examples/            stagehand-local, playwright, screenshot-first, shopping-approval, promptfoo
docs/                PRD, ARCHITECTURE, THREAT_MODEL, IMPLEMENTATION_PLAN, adr/
```

Dependency direction is strictly downward to `core` (ARCHITECTURE §3).

## Security-sensitive paths

Changes here are security-sensitive by definition: read the relevant
ARCHITECTURE/THREAT_MODEL sections first, name the invariants touched, add
fixtures, and expect maintainer review (see [GOVERNANCE.md](GOVERNANCE.md)).

- `packages/core/**` (all of it)
- `packages/policy/**`, `packages/vault/**`
- `packages/scanners/**` — especially decoders/normalizers and rule packs
- executor paths and wrappers in `packages/playwright/**`, `packages/stagehand/**`
- `packages/providers/**` request redaction and response validation
- `security-corpus/**` (never weaken or delete a fixture to make a change pass)
- `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/adr/**`, CI workflows

## Validation commands

Until M0 lands there is nothing to run — this is a documentation-only repo.
For docs changes, run the review-and-validation pass in
`docs/DOC_REVIEW_PROMPT.md`: every relative link and `#anchor` resolves, and
the legacy-name scan (`grep -rni agentfence . --exclude-dir=.git | grep -vi
openagentfence`) returns only the historical locations named in ADR-0007
(the PRD revision history, ADR-0007, and this file's rename note). Once the
baseline exists, the required local pipeline is, in order:

```text
pnpm lint  ->  pnpm typecheck  ->  pnpm test  ->  pnpm test:integration
  ->  openagentfence test --corpus security-corpus/   (from M7 onward)
```

The exact scripts are defined by OAF-REPO-002/003; if they differ from the
above, the package.json scripts win and this section must be updated.

### Validation execution under tool time limits

When a combined validation command exceeds an execution environment's time
limit, do not treat that timeout alone as an unresolved validation failure.
Run the required commands individually, in the documented order, and record
each exact result. Stop only if an individual required check fails, cannot be
run after reasonable environment-scoped recovery, or exposes a substantive
security or architecture blocker. Do not ask the user to run routine local
validation that the agent can execute this way.

## Coding standards

- TypeScript 5.x, `strict: true`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`; Node >= 20; **ESM-first**.
- **No `any` in exported/public APIs.** Use precise types or `unknown` with
  validation.
- Every scanner and provider call supports **cancellation and timeouts**
  (`AbortSignal` + deadline) and reports timeouts as such, never as `allow`.
- **Bounded parsing and decoding**: size, depth, and time limits on every
  decoder, normalizer, DOM/ARIA parser, YAML/JSON loader.
- **Schema validation at trust boundaries** (application input, page
  observations, guard-model responses, policy files, plugin manifests,
  traces on replay).
- **No arbitrary deserialization** (no `eval`, no `Function`, no
  prototype-polluting merges, no YAML custom tags).
- **No arbitrary code execution by plugins**: explicit registration only,
  no remote code loading.
- Stable, machine-readable reason codes for every decision; redaction by
  default in anything that can be logged.
- ESLint (typescript-eslint strict) + Prettier clean; Conventional Commits;
  DCO sign-off (`git commit -s`).

## Task execution procedure

For each implementation task (usually an `OAF-*` ID from
`docs/IMPLEMENTATION_PLAN.md`):

1. **Read** the task, its dependencies, and the referenced sections of the
   PRD, ARCHITECTURE, THREAT_MODEL, and ADRs.
2. **Identify affected security invariants** (`INV-nn`) and trust
   boundaries (`TBn`); write them into your plan/PR description.
3. **Implement the smallest coherent change** that satisfies the acceptance
   criteria. No speculative abstractions.
4. **Add tests** (unit; integration where behavior touches a browser or
   adapter).
5. **Add an attack/regression fixture** if the change is security-related.
6. **Run required validation**: lint, typecheck, unit, integration, security
   corpus (whatever exists at that point in the plan).
7. **Update docs** if behavior, configuration, defaults, or public API
   changed (package README, `docs/`, changeset).
8. **Do not proceed past unresolved failing tests.** Fix or report; never
   skip, delete, or loosen a failing security test.
9. **Report** what was done, what was verified, what was left out and why,
   and any conflicts discovered.

## Long-running prompt-series execution

When a user authorizes a persisted prompt series to run autonomously, the
series' `SERIES.md` is the durable execution authority for its approved scope,
sequencing, and pre-approved decisions. Execute ready prompts consecutively;
do not stop for routine implementation choices, ordinary test failures, API
report/docs/changeset updates, or an expected unsupported framework surface.

- Before kickoff, the plan author must move foreseeable architecture, ordering,
  compatibility, capability-gap, and optional-provider decisions into a dated
  decision register with an explicit fail-closed default. The maintainer
  reviews and approves that register before execution begins.
- During execution, apply a registered decision directly, record measured
  evidence in durable state, and continue. An unavailable hook must disable or
  constrain the relevant secure surface and be documented as `observed_only`
  or `unavailable`; it is not permission to fabricate enforcement or a reason
  to pause the whole series.
- Treat validation as an implementation loop: diagnose, repair within scope,
  rerun, and continue. Do not stop merely because a check initially fails.
- Completing an individual `PS-xxx` prompt is progress, not a terminal
  condition. After durable state is updated, select the next ready prompt and
  continue in the same authorized run. Do not send a final response merely to
  report prompt completion, a routine validation fallback, or the availability
  of later work; use a concise progress update instead. A terminal response is
  appropriate only after the whole-series definition of done is proven or a
  declared human-review stop condition has been reached.
- **Terminal-response guard:** before ending any turn during an authorized
  series run, reconcile `SERIES.md` and `STATE.md`. If any selected prompt is
  `in_progress`, or any dependency-satisfied prompt is `ready`, do not return a
  final response: persist the current checkpoint, select/resume that prompt,
  and continue. A context/tool/session interruption is likewise not a blocker;
  resume from durable state on the next turn. Never convert an unfinished
  execution loop into a status-only handoff without a declared stop condition.
- **Progress communication:** while a long command, test suite, or required
  read-only work unit is running, send brief commentary updates, but treat
  them as non-terminal. On every prompt boundary, state the next prompt being
  started and its purpose rather than asking whether to continue.
- Stop for human review only when reasonable in-scope remediation cannot
  preserve a normative security invariant; higher-priority sources conflict;
  a new security-critical dependency, material security/API posture change,
  external authority, credential, destructive action, or unplanned user choice
  is required; or an explicit pre-kickoff gate remains unapproved.
- Whenever a real stop condition must be surfaced, provide the evidence, one
  or more concrete safe resolutions, and a recommended path with the exact
  approval, ADR, or plan update needed. Do not merely report a blocker or ask
  the maintainer to rediscover the solution.
- A deferred control remains owned by its designated future prompt. Earlier
  prompts must not duplicate it or claim coverage; instead they must prevent a
  clean bypass and document the boundary for the owning prompt.
- The primary agent owns all integration, product edits, validation, durable
  series status, and completion decisions. Read-only subagents supply evidence,
  not stop authority. If their work is unavailable, the primary performs the
  bounded analysis itself.

Prompt-series plans must keep these defaults self-contained so a fresh agent
can continue from disk without conversational clarification. This procedure
does not override the source-of-truth order, ADR requirement, fail-closed
behavior, or the prohibition on weakening tests and deterministic controls.

## ADR requirement

Create or propose an ADR (`docs/adr/`, MADR-style, using
`0000-template.md`) whenever a decision materially changes architecture or
security posture: scanner contract, policy semantics or precedence, secret
trust boundaries, taint/provenance semantics, adapter boundaries, fail-closed
behavior, required dependencies, new runtime language, or project identity.
Open it as `Proposed`; a maintainer accepts it. Do not implement against a
`Proposed` ADR as if it were `Accepted` unless the task says so.

## Community and governance

Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Maintainer roles,
decision mechanisms, and the review requirement for security-sensitive
paths are in [GOVERNANCE.md](GOVERNANCE.md).

## Things to surface rather than decide

- Any conflict between the PRD, ARCHITECTURE, THREAT_MODEL, or ADRs.
- Any open question in `docs/ARCHITECTURE.md` §18 that your task forces you
  to resolve — resolve it explicitly (ADR or documented decision), do not
  bury it in code.
- Any place where a framework (Stagehand, Playwright) offers no hook to
  enforce a required control — document the gap, recommend a fail-closed
  disposition, and do not pretend coverage.
