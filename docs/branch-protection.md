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
current GitHub repository. On 2026-08-20, the remote `main` protection endpoint
returned `404` and repository rulesets were empty; the deployed workflow list
also did not include this TypeScript CI workflow. Local workflow validation and
the executable corpus gate are complete, but a maintainer must configure and
verify the required remote checks before the PS-025 release step. This remains
an external release-only gate under D-03.
