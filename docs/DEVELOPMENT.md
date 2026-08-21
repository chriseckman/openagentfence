# Development

Workspace commands and package boundaries for contributors and autonomous
coding agents. See also [AGENTS.md](../AGENTS.md) for the binding development
contract and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the task
breakdown.

## Prerequisites

- **Node.js >= 20** (see [`.nvmrc`](../.nvmrc)).
- **pnpm** — this repository uses the version declared in the root
  [`package.json`](../package.json) `packageManager` field. Enable it via
  Corepack:

  ```text
  corepack enable
  ```

- **Windows/macOS/Linux** are all supported for unit tests. Integration tests
  run headless Chromium on Linux in CI (M2 onward).

## Install and build

```text
pnpm install          # frozen lockfile in CI
pnpm build            # type-check + emit dist/ and .d.ts for every package
```

## Validation pipeline (in order)

```text
pnpm lint             # ESLint (strict, type-aware) + dependency-direction check
pnpm typecheck        # tsc --noEmit across all packages (turbo builds deps first)
pnpm test             # Vitest unit tests (core/policy/vault include coverage gate)
pnpm test:property    # seeded 1,000-run security properties and decoder/policy fuzzing
pnpm test:integration # local Playwright integration and fixture/corpus smoke tests
pnpm promptfoo:check  # Node >=22.22: offline Promptfoo config + local-provider eval
pnpm api-report       # regenerate API report baselines (etc/*.api.md)
pnpm docs:check       # relative Markdown link check
pnpm format:check     # Prettier check
```

`pnpm lint` includes `pnpm check:deps`, which enforces the dependency-direction
rules below from both declared `package.json` dependencies and source imports.
The Promptfoo example is a root-only development tool and is not a dependency
of any published package. Its dedicated CI job uses Node 24; the package
workspace continues to support the root Node 20 floor.

## Property and fuzz tests

The durable seed and run registry is [`fuzz/seeds.json`](../fuzz/seeds.json).
Every property in `core`, `scanners`, and `policy` runs at least 1,000 cases in
ordinary tests and in the dedicated PR job. A scheduled workflow raises the
bounded count to 10,000 with `OAF_PROPERTY_RUNS`; the harness rejects a count
below the PR floor or above 20,000.

Replay a minimized fast-check failure with
`OAF_PROPERTY_REPLAY=<property-id>=<path> pnpm test:property` while retaining
the registered seed. A counterexample must be repaired and committed as a
synthetic deterministic fixture before the property can return green. See
[`fuzz/README.md`](../fuzz/README.md) for the fixture convention. Properties
use injected/pre-aborted signals and deterministic state rather than
wall-clock timing as a security oracle.

## Package boundaries

Dependency direction is strictly downward to `@openagentfence/core`, which is
the leaf (see [ARCHITECTURE.md §3](ARCHITECTURE.md)). The map enforced by
`scripts/check-dependency-direction.mjs`:

| Package | May depend on |
|---------|---------------|
| `core` | *(nothing)* |
| `policy`, `vault`, `scanners`, `providers` | `core` |
| `playwright` | `core` |
| `stagehand` | `core`, `playwright` |
| `testing` | `core`, `scanners`, `policy` |
| `cli` | `core`, `policy`, `scanners`, `testing`, `providers`, `vault` |

Rules: `core` never imports another `@openagentfence/*` package; adapters
(`playwright`, `stagehand`) never import `scanners` or `policy`; nothing imports
`cli`. Cross-package types flow *up* from `core` only. New edges touching
`core`, `vault`, or `policy` require an ADR.

## Packages

Each package is an ESM package with a `src/index.ts` entry point, a
`test/smoke.test.ts`, and (for `core`, `policy`, `vault`) a coverage-gated
Vitest config. Packages publish under `@openagentfence/*`; none are published
yet.
