# Branch protection

Settings to apply to the `main` branch (via GitHub branch protection). Recorded
here so CI configuration and merge policy stay in sync.

- **Pull requests only.** Direct pushes to `main` are rejected.
- **One approving review required.**
- **Required status checks:** `lint`, `typecheck`, `unit`, `integration`,
  `commitlint`, `dco`, `CodeQL`, `dependency-review`. The Linux Chromium
  `integration` job is enabled for M2; `security-corpus` remains an M7
  placeholder and must not be required yet. The integration job uploads only
  schema-validated, raw-secret-checked synthetic trace artifacts.
- **Linear history.** Squash or rebase merges only; no merge commits.
- **No force pushes**, no history rewrite of `main`.
- **Conversations resolved** before merge.

Security-sensitive paths additionally require maintainer review via
[CODEOWNERS](../.github/CODEOWNERS) (see [GOVERNANCE.md](../GOVERNANCE.md)).
