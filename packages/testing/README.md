# @openagentfence/testing

Offline fixture, corpus, benchmark, and assertion utilities for OpenAgentFence.

## Fixture server

`startFixtureServer({ root, origins })` binds only ephemeral
`127.0.0.1` ports. Each origin ID maps to a distinct origin. The optional
`root` is served read-only with traversal, symlink, file-size, URL, header,
body, origin-count, and capture-count bounds. Fixed helpers cover redirects,
form/capture and bounded echo endpoints, downloads, popups, and scripted
mutation. Captures expose method, URL, origin, bounded headers/body, total body
bytes, and truncation state. The server performs no outbound requests.

## Corpus contract

The strict schema version is `1.1.0`. `loadCorpusFile()` validates the closed
manifest and all referenced local fixtures. Cases use the A1-A20 and
INV-01-INV-21 vocabularies, explicit surfaces and initiators, bounded static,
mutation, or adaptive-ready metadata, and immutable expected outcomes.
Adaptive metadata is inert: it cannot replace trusted task, policy, capability,
or expected fields.

`corpusHash()` is SHA-256 over the schema version, validated cases sorted by
case ID, and referenced fixture SHA-256 digests sorted by normalized path.
Manifest ordering therefore does not change the hash; any case or fixture
content change does. `corpusVitestCases()` and `runCorpusCases()` provide the
deterministic runner seam used by generated suites and the later CLI gate.

Assertion helpers include `expectBlocked`, `expectVerdict`, `expectFinding`,
and registry-aware `expectNoRawSecretIn(value, sentinels[])`. See the
[corpus contribution guide](../../security-corpus/README.md).

## Benchmark runner

`runBenchmark()` executes a closed case selection once with controls disabled
and once with controls enabled. Explicit per-case applicability fixes metric
denominators; unsupported outcomes are never converted to zero. Reports pin the
fixture-inclusive corpus hash, policy, exact framework/browser/agent/provider
versions and models, seed, and runner version. JSON reports are strictly
validated and integrity-hashed; Markdown is rendered only from a valid report.
Network mutation results retain initiator/surface/enforcement breakdowns, while
actual token/cost fields remain unsupported unless a harness measures them.

The offline `pnpm benchmark:pr` fixture is the bounded CI smoke run. It also
replays every current fixture after snapshot, measures deterministic scan,
high-impact authorization, and network-evaluator latency, and checks the
benign Tier 2 invocation and hard-block populations. CI writes only bounded,
value-free measurement metadata. The current pinned local result and its
limitations are documented in [benchmark definitions](../../docs/benchmarks.md);
no model recommendation is published.

## Local validation

```text
pnpm --filter @openagentfence/testing lint
pnpm --filter @openagentfence/testing typecheck
pnpm --filter @openagentfence/testing test
pnpm benchmark:pr
pnpm --filter @openagentfence/playwright test:integration
```

This package is experimental through v0.3 and is never imported by production runtime paths.
Every package-root export is experimental through v0.3; see the
[v0.1 API stability ledger](../../docs/api-stability.md).
## Security invariant gate

The package owns the 21-file INV-01 through INV-21 gate and the removal-sensitive
A1 through A20 deterministic coverage registry. Run it with
`pnpm --filter @openagentfence/testing test:invariants` or, from the repository
root, `pnpm test:invariants`. See
[the invariant-suite documentation](../../docs/invariant-suite.md).
