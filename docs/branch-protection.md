# Branch protection

Settings to apply to the `main` branch (via GitHub branch protection). Recorded
here so CI configuration and merge policy stay in sync.

- **Pull requests only.** Direct pushes to `main` are rejected.
- **One approving review required.**
- **Required status checks:** strict (head must include the current `main`)
  checks from the expected GitHub App: `Lint`, `Typecheck`, `API report`, all
  nine `Unit (Node, OS)` matrix rows, `Property and fuzz security suite (1,000
  runs/property)`, `Stagehand 4.0.1 conformance (Node 22.18.0)`, `Promptfoo
  0.122.0 offline example (Node 24)`, `Integration (headless Chromium)`,
  `Security corpus regression (headless Chromium)`, `Security invariants
  (INV-01 through INV-21)`, `Reproducible benchmark and control-performance
  smoke`, `Documentation and examples`, `Release candidate artifact audit
  (Node 24)`, `Dependency advisory audit`, `Conventional commits`, `DCO
  sign-off`, and `dependency-review`. The GitHub Advanced Security `CodeQL`
  check is independently required. The Linux Chromium integration,
  OAF-TEST-013 property/fuzz, and OAF-TEST-012 corpus checks are therefore
  mandatory before merge. The corpus job validates the strict corpus contract,
  installs Chromium, runs `openagentfence test --corpus`, and uploads only a
  bounded JUnit report. It rejects snapshots and raw executor errors; it does
  not upload page content or credentials.
- **Linear history.** Squash or rebase merges only; no merge commits.
- **No force pushes**, no history rewrite of `main`.
- **Conversations resolved** before merge.

Security-sensitive paths additionally require maintainer review via
[CODEOWNERS](../.github/CODEOWNERS) (see [GOVERNANCE.md](../GOVERNANCE.md)).

## Remote verification status

On 2026-08-22, repository ruleset `21170629` (`main-release-protection`) was
activated for the default branch with no bypass actors, pull-request-only
updates, one approving review plus CODEOWNERS and resolved conversations,
linear history, deletion/force-push restrictions, and the exact strict checks
above. The legacy `main` protection endpoint still returns `404` because this
is a repository ruleset rather than a legacy branch-protection record.

The dependency graph remains unavailable: GitHub's dependency-review action
currently fails before review, and its dependency-SBOM endpoint returns `404`.
Until an administrator enables **Settings → Advanced Security → Dependency
graph** and a fresh `dependency-review` run succeeds, D-03 is not fully proven.
The remote also has no `release` environment (only `copilot` and `pypi`), so
protected release-environment, signing-custody, and trusted-publisher evidence
is absent. Those are external release-only gates under D-03/D-04.

The local [release pipeline](release-pipeline.md) is also configured for a
protected `release` environment, CI-only OIDC/npm provenance, artifact
attestation, and signed tags. Those are required remote settings, not present
remote evidence. They remain unavailable until a maintainer configures and
verifies them during PS-025.
