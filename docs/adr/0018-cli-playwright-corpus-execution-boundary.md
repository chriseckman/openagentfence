# ADR-0018: CLI composition boundary for Playwright corpus execution

- **Status:** Accepted
- **Date:** 2026-08-20
- **Related:** PRD §§19.3, 27 item 24, 29.4; Architecture §3; OAF-TEST-012; INV-02, INV-05, INV-17

## Context

The P0 `openagentfence test --corpus` command must execute the security corpus
against the current packages in headless Playwright, produce deterministic
text/JSON/JUnit reports, and fail CI on a regression. The existing real case
executors are private Playwright integration-test code. The shipped testing
package exposes strict corpus loading and a framework-neutral sequential
runner, but no concrete browser executor.

Architecture §3 currently permits `@openagentfence/cli` to depend on core,
policy, scanners, testing, providers, and vault, but not on the Playwright
adapter. Testing may use Playwright as a peer/dev dependency, while the
Playwright adapter already dev-depends on testing; moving the concrete adapter
into testing would create the wrong package direction or duplicate adapter
logic. Comparing a case only with its declared expected outcome, importing
unpublished test files, or shelling out to a workspace Vitest command would not
implement a truthful published regression command.

## Decision

Permit the top-level `@openagentfence/cli` package to depend directly on
`@openagentfence/playwright` for commands whose documented purpose requires a
concrete Playwright execution backend. Declare `playwright` as the corresponding
peer/runtime prerequisite and fail with a typed, value-free unavailable result
when it is absent.

The CLI remains orchestration-only:

- security decisions stay in core, policy, scanners, vault, and the adapter;
- the CLI may compose those packages, start a bounded local fixture/browser
  harness, execute corpus cases, and render validated results;
- it may not reimplement probes, scanners, authorization, sink resolution,
  policy precedence, or adapter state revalidation;
- adapter packages never import CLI, scanners, or policy;
- corpus execution uses only loopback fixtures and synthetic values by default;
- adding another concrete execution backend requires an explicit supported
  command surface and the same dependency-direction review.

## Options considered

- **Put the executor in `@openagentfence/testing`.** Rejected because a real
  executor needs the concrete adapter, while Playwright already uses testing
  for fixtures; this creates a package cycle or duplicates adapter behavior.
- **Use an application-supplied execution plugin.** Viable later, but it leaves
  the required built-in P0 command without an executor and introduces a larger
  plugin-loading/security surface.
- **Shell out to repository Vitest files.** Rejected because published packages
  do not ship those files and a workspace/package-manager dependency is not a
  stable CLI contract.
- **Compare corpus metadata with expected outcomes.** Rejected because it does
  not execute controls and cannot detect a weakened rule.

## Consequences

- The CLI becomes the explicit top-level composition root for the Playwright
  corpus command.
- CLI installation/runtime documentation must state the Playwright prerequisite
  and exact locally verified version evidence.
- Dependency-rule tests and Architecture §3 must add only the
  `cli -> playwright` edge; all lower-layer rules remain unchanged.
- Corpus command tests must prove no security logic is duplicated, a deliberate
  isolated weakening fails, missing Playwright fails safely, and reports contain
  no raw synthetic secret.

## Security impact

This decision does not grant the CLI authorization authority. It enables
executable INV-02 coverage while preserving INV-05 redaction and INV-17 reason
reporting. The dependency edge is one-way into the existing adapter and does
not change core, policy, vault, scanner, or executor trust boundaries.

## References

- [PRD regression corpus](../browser-agent-firewall-prd.md#193-regression-corpus)
- [Architecture package boundaries](../ARCHITECTURE.md#3-package-boundaries)
- [Threat-model invariants](../THREAT_MODEL.md#6-security-invariants)
