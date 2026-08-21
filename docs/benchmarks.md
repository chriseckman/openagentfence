# Reproducible benchmarks

OpenAgentFence has benchmark infrastructure, but it does not yet publish a
v0.1 performance or efficacy result. Numbers in the PRD are illustrative
targets. A result becomes a project claim only after the M8 measurement gate
runs the current corpus and publishes its pinned report.

`@openagentfence/testing` exposes `runBenchmark()`, a framework-neutral,
sequential guarded-versus-unguarded runner. Both arms receive the same validated
corpus case and deterministic per-case seed. The only intended difference is
`controlsEnabled`. The CI fixture uses a bounded scripted agent that reads a
committed page and follows its explicit `data-oaf-scripted-instruction` marker;
it never derives an observed result from `CorpusExpected`.

## Reproducibility contract

Every report contains the corpus schema and fixture-inclusive SHA-256 hash,
policy hash, runner version, seed, exact framework and browser versions, exact
primary-agent model identifier, and every guard-provider/model identifier.
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
usage data and exact pins. PS-019 owns hardware/repetition/variance metadata,
the full current measurement, target evaluation, and any evidence-based tuning.
