# Branch protection

Settings to apply to the `main` branch (via GitHub branch protection). Recorded
here so CI configuration and merge policy stay in sync.

- **Pull requests only.** Direct pushes to `main` are rejected.
- **One approving review required.**
- **Required status checks:** `lint`, `typecheck`, `unit`, `property-fuzz`, `integration`,
  `commitlint`, `dco`, `CodeQL`, `dependency-review`. The Linux Chromium
  `integration` job, the seeded 1,000-run OAF-TEST-013 `property-fuzz` job,
  and the OAF-TEST-001/002 `security-corpus` foundation job are enabled. The
  latter is not the full M7 CLI regression gate and must not
  be required until OAF-TEST-012 lands. The integration job uploads only
  schema-validated, raw-secret-checked synthetic trace artifacts.
- **Linear history.** Squash or rebase merges only; no merge commits.
- **No force pushes**, no history rewrite of `main`.
- **Conversations resolved** before merge.

Security-sensitive paths additionally require maintainer review via
[CODEOWNERS](../.github/CODEOWNERS) (see [GOVERNANCE.md](../GOVERNANCE.md)).
