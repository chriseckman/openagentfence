# ADR-0015: Trusted navigation-origin binding

- **Status:** Accepted
- **Date:** 2026-08-18
- **Accepted:** 2026-08-18 by maintainer authorization
- **Related:** ADR-0010; PRD §13.7, §13.11; INV-08, INV-12, INV-14, INV-19

## Context

`READ_ONLY` permits same-site navigation only when it is an observed link
activation. The pre-existing canonical action contract records a destination
but not its trusted navigation origin, so it cannot safely distinguish a link
activation from direct, tool, model, or script navigation.

## Decision

1. `CanonicalAction` carries immutable `navigationOrigin: "link" | "direct"`
   for `NAVIGATE` actions.
2. Only an adapter-observed browser link activation may produce `link`.
   Tool/model/script and unverified navigation are `direct`.
3. The value is bound into `ActionIntent` and revalidated before execution.
4. In `READ_ONLY`, only same-site `NAVIGATE` with `navigationOrigin: "link"`
   is permitted. Missing or invalid values fail closed as `direct`.

## Consequences

- Adapters, state binding, tests, public API reports, documentation, and
  changesets must carry the bounded field.
- Existing callers without observed-link evidence remain safely `direct`.

## Security impact

This preserves fail-closed authority narrowing and exact structured execution.
Regression tests cover forged/missing values and READ_ONLY navigation.
