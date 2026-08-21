# Reproducible benchmarks

OpenAgentFence publishes one pinned **local control measurement** below. It is
not remote-CI, browser end-to-end, live-provider, model-efficacy, or general
production-performance evidence. Numbers in the PRD remain illustrative
targets unless a result states its exact runner, corpus hash, and scope.

`@openagentfence/testing` exposes `runBenchmark()`, a framework-neutral,
sequential guarded-versus-unguarded runner. Both arms receive the same validated
corpus case and deterministic per-case seed. The only intended difference is
`controlsEnabled`. The CI fixture uses a bounded scripted agent that reads a
committed page and follows its explicit `data-oaf-scripted-instruction` marker;
it never derives an observed result from `CorpusExpected`.

## Reproducibility contract

Every report contains the corpus schema and fixture-inclusive SHA-256 hash,
policy hash, runner version, seed, exact framework and browser versions, exact
primary-agent model identifier, every guard-provider/model identifier, and a
closed runner/environment pin (runner class, operating system, exact Node
version, and CPU count). The current generic paired runner records exactly one
unguarded-then-guarded repetition with zero warm-ups; a future multi-run runner
must add, validate, and report its own repetition/variance contract rather than
claiming it through this schema.
Providerless or browserless scripted runs use the explicit version
`not_applicable`, never an omitted or inferred pin. Version ranges, `latest`,
`default`, and `auto` model identifiers are rejected.

Each selected case declares a closed applicability entry. This is the metric
population: generic corpus tags do not decide whether a case counts as an
exfiltration, resolver-bypass, restricted-recovery, or ActionIntent-mismatch
attempt. Exactly one guarded and one unguarded observation is required per
case. Missing evidence is `unsupported`, not zero and not clean.

The JSON boundary is the closed
[`benchmark-report.schema.json`](../packages/testing/src/schemas/benchmark-report.schema.json)
contract plus `parseBenchmarkReport()`. Runtime validation recomputes aggregates,
paired comparisons, and the report hash from case measurements. The hash is a
content fingerprint, not a signature or authenticity proof. Markdown is a
rendering of the already validated report.

## Metric definitions

For each outcome, `success` means the event named by the metric occurred.
Therefore lower is better for attack, exfiltration, unauthorized action/origin/
network mutation, secret-resolution bypass, and false-positive rates; higher is
better for injection detection, legitimate completion, restricted recovery,
and ActionIntent-mismatch blocking.

- The denominator is `success + failure` among explicitly applicable cases.
  `unsupported` and `not_applicable` are separately counted.
- False positive means a benign task was hard-blocked or quarantined; warning
  or safe sanitization alone is not a false positive.
- Network mutation evidence records attempted/succeeded counts grouped by
  actual initiator, surface, and `enforced`/`observed_only`/`unavailable`
  capability. Observed or unavailable traffic is never presented as enforced.
- Guard invocation reports cases with an invocation, total calls, calls per
  applicable opportunity, conservative reserved tokens, and separate call- and
  token-budget exhaustion.
- Added latency is the median of per-case `(guarded - unguarded)` deltas. This
  whole-task measurement is not the later PRD deterministic-scan or pre-action
  microbenchmark.
- Tokens and USD cost are actual measured usage only. Core guard-token
  reservations are reported separately and are never relabelled as usage.
  If a provider does not supply measured usage, totals and deltas are `null`.

## Bounded profiles

| Profile | Maximum cases | Per-case deadline | Run deadline | Purpose |
| --- | ---: | ---: | ---: | --- |
| `pr` | 12 | 5 s | 60 s | Offline deterministic fixture subset (`pnpm benchmark:pr`) |
| `nightly` | 1,024 | 30 s | 30 min | Larger reproducible scheduled runs |
| `full` | 4,096 | 60 s | 60 min | M8 pinned release-candidate measurement |

The PR job makes no live provider call and needs no credential. Optional real
agent/provider runners are application-owned, opt-in, and must supply actual
usage data and exact pins.

## M8 pinned control measurement — 2026-08-21

This is the first v0.1 measurement. It was produced by
`packages/testing/test/performance.test.ts` with `pnpm benchmark:pr`; the same
test runs in the configured CI benchmark job and writes a value-free JSON
artifact when `OAF_BENCHMARK_ARTIFACT_DIR` is set. It is a local runner result,
not a claim that an undeployed remote GitHub Actions workflow has run.

| Field | Pinned value |
| --- | --- |
| Date | `2026-08-21T19:59:00.155Z` |
| Corpus | schema `1.1.0`, 227 cases, 31 fixture files, SHA-256 `4c45eece9b8d6b606b39077f31146521b837f62ad4780fa6b9ebce3e2ccf185e` |
| Components | `@openagentfence/core`, `@openagentfence/scanners`, and `@openagentfence/testing` `0.0.0`; Vitest `3.2.7`; browser and primary agent `not_applicable`; offline fixture guard only, with no external provider/model |
| Runner | `local-node`, Windows `win32-x64`, Node `v24.19.0`, 8 logical CPUs, AMD Ryzen 5 2400G with Radeon Vega Graphics |
| Scan configuration | all 31 fixture bytes replayed as bounded post-snapshot web `ProbeResult` inputs; 5 fixture warm-ups and 7 repetitions (217 samples); the phase-specific subset of the 14-entry default scanner catalog |
| Authorization configuration | 120 fresh-session `DELETE` authorizations under secure-default policy hash `4dd7c765563aa3cd88ebb51f6b4c4681c64b3c16e45edfc58edb8efb64fcba3f`, no approval handler and no semantic provider |
| Network configuration | 25 warm-ups and 500 pure, enforced same-origin fetch evaluations with an explicit clean bounded egress inspection |
| Semantic/FP configuration | all 66 benign corpus cases scanned with the optional Tier 2 selector and an offline schema-valid non-authoritative fixture classifier |

### Results and target status

| Measure | Median | p95 | Mean / standard deviation | Target status |
| --- | ---: | ---: | ---: | --- |
| Deterministic post-snapshot page scan | 0.629 ms | 1.656 ms | 0.764 / 0.471 ms | Meets the PRD `<100 ms` median target on this runner |
| High-impact deterministic pre-action authorization | 0.158 ms | 0.378 ms | 0.231 / 0.336 ms | Meets the PRD `<50 ms` median target on this runner |
| Pure network-guard evaluation | 0.027 ms | 0.052 ms | 0.031 / 0.016 ms | Supporting measurement; the PRD has no standalone threshold |
| Benign hard blocks / observations | 0 / 66 (0%) | n/a | n/a | Meets the PRD `<2%` benign hard-block target on this corpus population |
| Optional Tier 2 invocations / benign observations | 11 / 66 (16.67%) | n/a | n/a | Avoided for 55 / 66 (83.33%): a majority of benign observations |

The microbenchmark intentionally excludes browser navigation, DOM snapshot
collection, network I/O, live provider latency, and application task
completion. Its `ProbeResult` replay is an after-snapshot control measurement,
not a browser end-to-end latency claim. The existing 227/227 corpus CLI run is
separate behavioral evidence; it must not be reinterpreted as a legitimate
completion-rate benchmark. No Ollama model is measured or recommended.

No scanner rule, policy threshold, capability, source/sink check, or approval
default was tuned for this result: the paired benign outcome is already zero
hard blocks, and weakening a deterministic control would violate ADR-0003 and
INV-03/09/12/20. CI regression ceilings are deliberately more generous than
the PRD targets—500/1,500 ms scan median/p95, 250/750 ms authorization
median/p95, and 100 ms network p95—so they catch material slowdowns without
turning environment variance into a false security or release result.
