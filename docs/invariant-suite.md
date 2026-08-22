# Security invariant suite

The required M7 invariant gate is an executable, offline suite with exactly
one named group for each security invariant in
[THREAT_MODEL.md §6](THREAT_MODEL.md#6-security-invariants):
`packages/testing/test/invariants/INV-01.spec.ts` through
`INV-21.spec.ts`.

Run it from the repository root:

```sh
pnpm test:invariants
```

The shared registry binds every invariant to its trust boundaries,
deterministic controls, corpus cases, and focused executable evidence. INV-02
also maintains a closed A1–A20 control registry and deliberately removes each
class, control, and fixture in turn to prove that missing coverage fails the
gate. Every scenario is checked by the registry-aware exact and normalized
secret-leak oracle.

The suite is framework-neutral to preserve package dependency direction.
Adapter-specific browser and Stagehand evidence remains in those packages and
is linked from the registry and Threat Model. An adapter surface classified as
`observed_only` or `unavailable` is evidence of a capability gap, never an
enforcement claim.

CI runs this suite in the dedicated `invariants` job. A vulnerability fix must
add or strengthen an invariant scenario or a minimized corpus regression case;
it must not weaken an existing control or fixture.
