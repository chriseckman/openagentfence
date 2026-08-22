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
pnpm lint             # ESLint (strict, type-aware) + dependency/workflow checks
pnpm typecheck        # tsc --noEmit across all packages (turbo builds deps first)
pnpm test             # Vitest unit tests (core/policy/vault include coverage gate)
pnpm test:property    # seeded 1,000-run security properties and decoder/policy fuzzing
pnpm test:integration # local Playwright integration and fixture/corpus smoke tests
pnpm test:corpus      # shipped loopback-only Playwright corpus CLI
pnpm test:invariants  # INV-01 through INV-21 and removal-sensitive coverage registry
pnpm benchmark:pr     # bounded offline control-measurement regression check
pnpm promptfoo:check  # Node >=22.22: offline Promptfoo config + local-provider eval
pnpm audit:dependencies # fail on any dependency advisory
pnpm api-report       # regenerate API report baselines (etc/*.api.md)
pnpm docs:check       # Markdown links, docs/source tables, and TypeDoc build
pnpm examples:check   # compile and run the no-network secure quick start
pnpm format:check     # Prettier check
```

`pnpm lint` includes `pnpm check:deps` and `pnpm check:workflow`, which enforce
the dependency-direction and workflow-pinning rules below. The Promptfoo example
requires Node 22.22 or newer; repository CI uses Node 24 for that separate job.
It is a root-only development tool and is not a dependency of any published
package. The package workspace continues to support the root Node 20 floor.

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
| `cli` | `core`, `policy`, `scanners`, `testing`, `providers`, `vault`, `playwright` (bounded corpus/diagnostic composition only; ADR-0018) |

Rules: `core` never imports another `@openagentfence/*` package; adapters
(`playwright`, `stagehand`) never import `scanners` or `policy`; nothing imports
`cli`. Cross-package types flow *up* from `core` only. New edges touching
`core`, `vault`, or `policy` require an ADR.

## Packages

Each package is an ESM package with a `src/index.ts` entry point, a
`test/smoke.test.ts`, and (for `core`, `policy`, `vault`) a coverage-gated
Vitest config. Packages are prepared for public publication under
`@openagentfence/*`; verify the current npm publication state through the
[v0.1 release checklist](release-checklist-v0.1.md) rather than inferring it.
