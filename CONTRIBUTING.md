# Contributing to OpenAgentFence

Thank you for your interest in OpenAgentFence, an open-source security
firewall for AI browser agents. This document explains how to contribute
without weakening the guarantees the project exists to provide.

Before contributing, read (in this order):

1. [SECURITY.md](SECURITY.md) — security model and vulnerability reporting.
2. [docs/browser-agent-firewall-prd.md](docs/browser-agent-firewall-prd.md) — what and why.
3. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — boundaries you must respect.
4. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — invariants your change must not break.
5. [docs/adr/](docs/adr/README.md) — accepted decisions.
6. [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) — what is being built and in what order.

Autonomous coding agents must additionally follow [AGENTS.md](AGENTS.md).

## Development principles

- **Security correctness over feature velocity.** A slower, provably
  fail-closed change beats a fast one with an unexamined path.
- **Deterministic controls before probabilistic controls.** Every attack
  class needs a deterministic control; semantic classifiers add evidence.
- **No model output may override a deterministic critical block.** Not a
  guard model, not an ensemble, not the primary agent
  ([ADR-0003](docs/adr/0003-deterministic-authorization-is-final-boundary.md)).
- **Framework-specific behavior belongs in adapters.** `@openagentfence/core`
  must remain browser-framework-neutral (no Stagehand or Playwright imports)
  and model-neutral (no vendor SDKs, no bundled model)
  ([ADR-0002](docs/adr/0002-framework-neutral-core-with-adapters.md),
  [ADR-0004](docs/adr/0004-local-first-byok-semantic-classification.md)).
- **Secret values must not appear in logs, fixtures, tests, traces, events,
  findings, or approval requests.** Use handles and synthetic placeholders
  ([ADR-0005](docs/adr/0005-executor-side-secret-handles.md)).
- **Security regressions require regression fixtures.** Every fixed bypass
  becomes a permanent corpus fixture or invariant test.
- **Every public API change should be intentional.** Public surfaces are
  reviewed via the API report; experimental APIs are marked `unstable_` /
  `@experimental`.
- **Fail closed at critical boundaries.** Timeouts, exhausted budgets, and
  missing handlers deny high-risk actions.
- **Explain every block.** New decisions need stable reason codes and
  redacted evidence.

## Clean-room requirement (mandatory)

OpenAgentFence takes design inspiration from several projects (PRD §25,
§38). Two carry explicit constraints:

**Agent Browser Shield** is licensed under **PolyForm Shield 1.0.0**, which
restricts use of the software to build competing products. It may be used
**only as a product/design reference** (public documentation and observable
behavior). Contributors must **not**:

- copy its source code;
- port its implementation to TypeScript or any other language;
- translate its code, line-by-line or structurally;
- reproduce internal algorithms learned from its protected source;
- submit code substantially derived from that implementation.

Requirements must instead be implemented independently from:

- the OpenAgentFence PRD, architecture, and threat model;
- published standards (HTML, ARIA, WAI-ARIA accessible-name computation,
  CSS visibility semantics, URL/origin specifications, RFC 1918 and related
  address-range RFCs, Unicode normalization);
- public research on prompt injection and agent security;
- independent security reasoning; and
- permissively licensed references where appropriate, with attribution.

**LLM Guard** is MIT licensed but archived. Its architecture may be used
under MIT terms, but OpenAgentFence prefers independent, browser-agent-native
implementations rather than inheriting the archived runtime; it is not a
runtime dependency.

Process (PRD §29.7, [ADR-0006](docs/adr/0006-clean-room-implementation-policy.md)):

- Contributors to scanner internals attest in their pull request that they
  have not read Agent Browser Shield source. The pull-request template
  carries a checkbox for changes to scanner internals.
- ADRs and `docs/ARCHITECTURE.md` are the project's independent design
  record. Cite the public standard or paper a technique comes from in code
  comments or the package README.
- If you have read Agent Browser Shield source, say so and do not contribute
  to scanner internals; there is plenty of other work.

## Pull requests

Every pull request should have:

- **Focused scope.** One coherent change. No unrelated refactors, renames,
  or formatting sweeps.
- **Tests.** Unit tests for new logic; integration tests for adapter/browser
  behavior.
- **Security fixtures where applicable.** A change to a scanner, policy
  rule, guard, adapter execution path, or decoder must add or update
  fixtures in `security-corpus/` or the invariant test suite.
- **Documentation updates.** Package README, `docs/`, policy option docs
  (default + security impact), and the changelog via a changeset.
- **A changeset** for any public-API or user-visible change (once Changesets
  is configured in the repository).
- **A linked task or issue** (implementation-plan task IDs such as
  `OAF-CORE-003` are fine).
- **A note on invariants**: which `INV-nn` in the threat model the change
  touches, and how that is tested.

Pull requests that weaken a deterministic control, add a required network
dependency, add a dependency to a security-critical path, or change a
trust boundary will be held until an ADR is proposed and accepted.

## Testing

Planned standards (PRD §29.4, §21); they become enforced as the M0/M7 tasks
in the implementation plan land:

- **Vitest** for unit tests.
- **Playwright** drives integration tests against corpus pages served by a
  local fixture server (no network access in tests).
- **Deterministic attack corpus** in `security-corpus/`; run with
  `openagentfence test --corpus security-corpus/`; a required CI status
  check — any regression blocks merge.
- **Property-based testing** (fast-check) for aggregation precedence, policy
  evaluation, and normalizers where appropriate.
- **Fuzzing** for all decoders and normalizers (encoded-payload, Unicode,
  URL, DOM/ARIA parsing).
- **Invariant tests**: one or more tests per `INV-nn` in
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Coverage gate**: at least 85% lines/branches for `core`, `policy`, and
  `vault`.
- **No secrets in fixtures.** Use obviously synthetic values and the handle
  format where a secret is intended; CI secret scanning will reject
  real-looking credentials. Provider-authentication tests also use synthetic
  credentials and assert they never reach policy, classification content,
  structured errors, events, or traces.

Run the full local pipeline before opening a PR: lint, typecheck, unit,
integration (headless Chromium), security corpus.

## Commits

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `chore:`, `security:` for security fixes), enforced by commitlint once
  configured. Scope with the package name where useful, e.g.
  `feat(core): add capability envelope compiler`.
- **DCO sign-off** is required on every commit (`git commit -s`), certifying
  the [Developer Certificate of Origin](https://developercertificate.org/).
- Keep commits reviewable; squash noise before opening the PR.

## Architecture changes

Meaningful architectural changes require an Architecture Decision Record in
[docs/adr/](docs/adr/README.md) before or alongside the code. Examples that
always need an ADR:

- changing the scanner contract (`SecurityScanner`, `ScanResult`, `Finding`, phases);
- changing policy semantics, verdict precedence, or default behavior;
- adding a required cloud dependency, telemetry, or model vendor;
- changing secret trust boundaries (where raw values may exist, how handles resolve);
- changing taint/provenance semantics;
- introducing a new runtime language or native module;
- changing adapter boundaries (what `core` may know about a framework);
- weakening fail-closed behavior anywhere;
- adding a dependency to `core`, `policy`, `vault`, or a decoder.

Use `docs/adr/0000-template.md`. Open the ADR as `Proposed`; it becomes
`Accepted` when a maintainer merges it.

## Security contributions

- **Exploitable vulnerabilities**: do not open a public issue or PR. Follow
  [SECURITY.md](SECURITY.md).
- **Detection-quality improvements** (a missed injection that deterministic
  controls still contained): open an issue with a fixture, then a PR that
  adds the fixture and the improvement.
- **New attack fixtures** are welcome on their own; the corpus format is
  documented in `@openagentfence/testing` once it exists.

## Community

This project follows the [Contributor Covenant 2.1 Code of Conduct](CODE_OF_CONDUCT.md).
Decision-making and maintainer roles are described in [GOVERNANCE.md](GOVERNANCE.md)
(single maintainer initially, with the stated intent to expand to a
maintainers group before v1.0). Be respectful, assume good faith, and keep
discussions technical.

## License

By contributing you agree that your contributions are licensed under the
Apache License 2.0 and that you have the right to submit them under the DCO.
