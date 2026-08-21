# Branch protection

Settings to apply to the `main` branch (via GitHub branch protection). Recorded
here so CI configuration and merge policy stay in sync.

- **Pull requests only.** Direct pushes to `main` are rejected.
- **One approving review required.**
- **Required status checks:** `lint`, `typecheck`, `unit`, `property-fuzz`, `integration`,
  `security-corpus`, `invariants`, `commitlint`, `dco`, `CodeQL`, and
  `dependency-review`. The Linux Chromium `integration` job, seeded 1,000-run
  OAF-TEST-013 `property-fuzz` job, and OAF-TEST-012 `security-corpus` job are
  enabled in the repository workflow. The corpus job validates the strict
  corpus contract, installs Chromium, runs `openagentfence test --corpus`, and
  uploads only a bounded JUnit report. It rejects snapshots and raw executor
  errors; it does not upload page content or credentials.
- **Linear history.** Squash or rebase merges only; no merge commits.
- **No force pushes**, no history rewrite of `main`.
- **Conversations resolved** before merge.

Security-sensitive paths additionally require maintainer review via
[CODEOWNERS](../.github/CODEOWNERS) (see [GOVERNANCE.md](../GOVERNANCE.md)).

## Remote verification status

These settings are the required release configuration, not a claim about the
current GitHub repository. A fresh read-only verification on 2026-08-21 found
that the remote `main` protection endpoint still returned `404`, repository
rulesets were still empty, and only legacy Python/Copilot workflows were
deployed. The remote has no `release` environment (only `copilot` and
`pypi`), so protected release-environment, signing-custody, and trusted
publisher evidence is also absent. Local workflow validation and the
executable corpus gate are complete, but a maintainer must configure and verify
the required remote checks before the PS-025 release step. This remains an
external release-only gate under D-03/D-04.

The local [release pipeline](release-pipeline.md) is also configured for a
protected `release` environment, CI-only OIDC/npm provenance, artifact
attestation, and signed tags. Those are required remote settings, not present
remote evidence. They remain unavailable until a maintainer configures and
verifies them during PS-025.
