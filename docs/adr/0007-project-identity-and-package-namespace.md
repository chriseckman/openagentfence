# ADR-0007: OpenAgentFence project identity and package namespace

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD front matter, §34 (Decision 1 and open item 1)

## Context

The project began under the working title "Browser Agent Firewall" and was
briefly named **AgentFence** during PRD drafting. Before any implementation
began, registry checks found active, unrelated packages using the
`agentfence` name on npm and PyPI in the same general category, and an
alternative ("BrowserFence") matched an existing product. To avoid
project/package naming conflicts, the project was renamed prior to writing
code. This ADR records the resolved identity so that no document, package,
CLI, or configuration file carries a stale name.

## Decision

The public identity of this project is:

```text
Product:         OpenAgentFence
Repository:      chriseckman/openagentfence
Repository URL:  https://github.com/chriseckman/openagentfence
npm scope:       @openagentfence/*
CLI:             openagentfence
Primary class:   OpenAgentFence
Config file:     openagentfence.yml
Env prefix:      OPENAGENTFENCE_
License:         Apache-2.0
Copyright:       Copyright 2026 Christopher Eckman
```

Rules:

1. All packages publish under `@openagentfence/*` (for example
   `@openagentfence/core`, `@openagentfence/stagehand`,
   `@openagentfence/playwright`).
2. The CLI binary is `openagentfence`; a future PyPI distribution uses the
   name `openagentfence`.
3. The default policy/configuration filename is `openagentfence.yml`.
4. Project-specific environment variables use the `OPENAGENTFENCE_` prefix.
   Application-owned variables that appear in examples (such as a user's own
   `GUARD_API_KEY`) are not project variables and need not carry the prefix.
5. "AgentFence" is retained only in historical context (PRD revision
   history, this ADR). It must not appear in code, package names, CLI
   output, configuration keys, or current documentation as the name of this
   project.

## Scope limitation

This ADR concerns **project identity only**. It does not imply any
compatibility, lineage, endorsement, or relationship with any other project
that uses "AgentFence" or a similar name. The residual naming-association
risk noted in the PRD is mitigated by clear positioning. A trademark search
is not planned at this time (maintainer decision, 2026-08-15).

## Consequences

- Positive: consistent naming across repository, packages, CLI, config, and
  docs before the first line of product code.
- Follow-up: **done 2026-08-15** — the `@openagentfence` npm scope and the
  `openagentfence` PyPI name are reserved and the repository is
  `chriseckman/openagentfence`. If the meta-package in ADR-0008 is built,
  confirm the unscoped `openagentfence` npm name at that time. No trademark
  search is planned.

## Security impact

None.
