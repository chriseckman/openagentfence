# @openagentfence/cli

The CLI is an orchestration surface: it composes published core, policy,
scanner, vault, and Playwright APIs; it does not contain an independent
scanner, policy, or authorization implementation.

## Secure setup and diagnostics

```sh
openagentfence init
openagentfence policy validate openagentfence.yml
openagentfence doctor --json
openagentfence doctor --route-requests
openagentfence explain redacted-trace.json
```

`init` writes an explicit, validated `openagentfence.yml` with secure defaults:
unknown actions block, high-risk scanner failures block, navigation is
same-site with private networks blocked, secret resolution stays executor-only,
and high-impact actions are denied or require approval. It never writes provider
or credential configuration and refuses to overwrite an existing file unless
`--force` is explicit.

`policy validate` applies the bounded policy parser and static policy validator.
It reports only stable policy paths and warnings, never policy values or the
input path. It exits `0` when valid, `1` when invalid/unavailable, and `2` for
usage errors.

`doctor` is offline by default. It reports the current Node version, the tested
Playwright `1.62.1` version separately from its `>=1.40.0` peer range, and the
exact default or `--route-requests` network-capability matrix. Surfaces marked
`observed_only` or `unavailable` are gaps, not enforcement claims. The CLI does
not depend on Stagehand, so it reports that framework as `not_inspected` and
directs users to the Stagehand package capability ledger. Provider connectivity
is attempted only with explicit `--check-provider <http(s)-url>`; the result
does not render the endpoint, credentials, headers, body, or error details.

`explain` is presentation only: it bounds and validates a trace, rejects fields
outside its closed redacted projection, and renders only event kinds, timestamps,
stable decisions/reasons, and evidence hashes. It never replays scanners,
providers, or browser effects. Its input must already be a redacted compatible
trace; arbitrary fields, including raw task or provider data, are rejected.

## Corpus gate

After installing the CLI with its Playwright peer prerequisite, run:

```sh
openagentfence test --corpus security-corpus
openagentfence test --corpus security-corpus --filter class=A5 --reporter json
openagentfence test --corpus security-corpus --reporter junit --output artifacts/corpus/results.junit.xml
```

Within this repository, build first and use `pnpm test:corpus`. The command
uses only the local, loopback fixture server and synthetic corpus data. It
never makes live provider calls and rejects `--update-snapshots` in every
environment.

Exit status is `0` for a clean run, `1` for a security regression (including a
corpus attack class with no deterministic control), and `2` for invalid input
or an unavailable local runtime. Text, JSON, and JUnit reports contain the
canonical corpus hash, selected class totals, stable reason codes, and bounded
durations only; executor errors and raw fixture values are never reported.

## Requirements and limits

The concrete built-in backend is headless Playwright. `playwright` is a peer
dependency and must be installed with a compatible browser. The one-way
`@openagentfence/cli` → `@openagentfence/playwright` composition edge is
accepted in [ADR-0018](../../docs/adr/0018-cli-playwright-corpus-execution-boundary.md).
Other execution backends are not implied or dynamically loaded.

The repository CI configuration is locally validated. Required remote branch
protection and deployed GitHub workflow evidence are release-only checks; see
[branch-protection.md](../../docs/branch-protection.md).

The `openagentfence` binary is the supported CLI surface; no programmatic CLI
API is published. See the [v0.1 API stability ledger](../../docs/api-stability.md)
for package-root boundaries.
