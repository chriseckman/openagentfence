# @openagentfence/cli

The `openagentfence test --corpus` command is the v0.1 local security-corpus
gate. It composes the published core, scanner, vault, and Playwright adapter
packages; it does not contain an independent scanner, policy, or authorization
implementation.

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
