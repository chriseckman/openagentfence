# OpenAgentFence Governance

This document describes how decisions are made in the OpenAgentFence project
and how that will change as the project grows (PRD §29.7, §34 Decision 15).

## Current model: single maintainer

OpenAgentFence is currently maintained by a **single maintainer**,
Christopher Eckman ([@chriseckman](https://github.com/chriseckman)), who is
the copyright holder of the project's original code and documentation.

The maintainer:

- sets project direction and priorities (the PRD and implementation plan);
- reviews and merges pull requests;
- accepts, rejects, or supersedes Architecture Decision Records;
- triages issues and coordinates security response ([SECURITY.md](SECURITY.md));
- enforces the [Code of Conduct](CODE_OF_CONDUCT.md);
- cuts releases (from CI only; see PRD §29.6).

## How decisions are made

| Decision type | Mechanism |
|---------------|-----------|
| Day-to-day code changes | Pull request review against [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). |
| Architectural or security-posture changes | An ADR in [docs/adr/](docs/adr/README.md), opened as `Proposed`, discussed in the PR, and merged as `Accepted` by the maintainer. |
| Scope and priority changes | A PRD revision (with a revision-history entry) and, where the change is architectural, an ADR. |
| Security fixes | Private advisory workflow in [SECURITY.md](SECURITY.md); the maintainer may merge without the usual public review window, followed by a public regression fixture. |
| Code of Conduct enforcement | Per the enforcement guidelines in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). |

Decisions are recorded in the repository (ADRs, PRD revision history,
changesets, advisories), not in chat or private channels, so that
contributors and coding agents can rely on the written record.

## Security-sensitive paths

Changes to the following paths require maintainer review regardless of who
authored them (to be enforced through `CODEOWNERS` once the repository
baseline lands):

- `packages/core/`
- `packages/policy/`
- `packages/vault/`
- `packages/scanners/` (decoders, normalizers, scanner internals)
- adapter executor paths in `packages/playwright/` and `packages/stagehand/`
- request-redaction and response-validation paths in `packages/providers/`
- `security-corpus/`
- `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/adr/`
- CI workflows under `.github/workflows/`

## Planned evolution: maintainers group

Before v1.0 the project intends to expand to a **maintainers group**. When
that happens this document will be revised to define, at minimum:

- how maintainers are nominated and added (expected: sustained, high-quality
  contribution to security-sensitive areas, nominated by an existing
  maintainer, no objections from other maintainers);
- how maintainers step down or are removed;
- decision-making among maintainers (expected: lazy consensus for routine
  changes; explicit majority for ADRs, releases, and governance changes; a
  documented tie-break);
- which roles may access private security reports and release credentials;
- how CODEOWNERS is kept aligned with the maintainer roster.

Until then, contributors are welcome as reviewers and triagers at the
maintainer's discretion; such roles do not carry merge or release authority.

## Changes to this document

Governance changes are made by pull request and recorded in the revision
history below. Substantive changes are announced in the release notes.

| Date | Change |
|------|--------|
| 2026-08-15 | Initial governance: single maintainer, intent to expand before v1.0. |
