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
pnpm test:integration # integration tests (placeholder until M2)
pnpm api-report       # regenerate API report baselines (etc/*.api.md)
pnpm docs:check       # relative Markdown link check
pnpm format:check     # Prettier check
```

`pnpm lint` includes `pnpm check:deps`, which enforces the dependency-direction
rules below from both declared `package.json` dependencies and source imports.

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
