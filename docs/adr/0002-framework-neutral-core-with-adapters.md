# ADR-0002: Framework-neutral core with Stagehand and Playwright adapters

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §1, §16, §17, §29.1, §34 (Decision 9); [ARCHITECTURE.md](../ARCHITECTURE.md) § Stagehand architecture, § Playwright architecture

## Context

Stagehand is the first-class initial integration because it exposes AI
primitives (`observe`, `act`, `extract`) alongside deterministic browser
control, which gives the firewall a natural authorization boundary between a
*proposed* action and its *execution*. But the PRD requires that the core
security model depend on neither Stagehand nor Playwright, that Playwright be
usable without Stagehand, and that framework-neutral scanner and adapter
interfaces be publishable for other frameworks (Browser Use, browser MCP
servers, CDP automation).

## Decision

1. `@openagentfence/core` has **no dependency on Stagehand or Playwright**
   (neither runtime nor peer). It defines the `BrowserAdapter` contract and
   the framework-neutral `PageObservation` / `CanonicalAction` model, and
   ships the framework-neutral in-page probe used to collect DOM signals.
2. `@openagentfence/stagehand` is the **first-class adapter**. It targets
   Stagehand v4, declares Stagehand as a peer dependency with an explicit
   range, isolates all Stagehand-specific behavior, and implements the
   `observe -> normalize -> authorize -> act` pattern plus a bypass-resistant
   wrapper.
3. `@openagentfence/playwright` is an **independent adapter**. It must be
   usable with plain Playwright and must not import Stagehand.
4. Framework-specific behavior lives only in adapters. Anything an adapter
   needs from `core` is added to `core` in framework-neutral form.
5. Additional adapters are added as new packages implementing the same
   contract; no adapter may require changes to `core` semantics.

## Options considered

- **Build directly on Stagehand.** Rejected: framework lock-in; the PRD
  forbids it.
- **Playwright-only with Stagehand as an example.** Rejected: the Stagehand
  observe/act split is the strongest available authorization seam and the
  PRD makes it first-class.

## Consequences

- Positive: `core` can be reviewed and tested without a browser framework;
  new frameworks integrate without touching security logic.
- Negative: adapters must each cover the full execution surface of their
  framework to resist accidental bypass; this is ongoing maintenance as
  frameworks evolve.
- Follow-up: pin and test supported Stagehand minor versions in CI; keep the
  adapter compatibility matrix current.

## Security impact

Strengthens the "Stagehand does not leak into core" boundary and keeps the
authorization boundary reviewable in one place. Adapter completeness (no
uncovered execution path) becomes a tracked security property; see the
wrapper-coverage invariant in THREAT_MODEL.md.
