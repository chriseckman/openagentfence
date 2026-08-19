# ADR-0006: Clean-room implementation policy

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §1, §25, §29.7, §34 (Decision 11), §35, §38; [CONTRIBUTING.md](../../CONTRIBUTING.md) § Clean-room requirement

## Context

OpenAgentFence takes design inspiration from several existing projects. Two
require explicit handling:

- **Agent Browser Shield** (PixieBrix) is source-available under
  **PolyForm Shield 1.0.0**, which restricts use of the software to build a
  competing product. It may inform *what* OpenAgentFence does (product
  behavior, categories of hidden-content rules, benchmark methodology) but
  not *how* it is implemented.
- **LLM Guard** (Protect AI) is **MIT licensed but archived**. Its
  architecture (composable scanners, sanitization as an outcome, risk
  scores, anonymize/deanonymize) may be used under MIT terms, but adopting
  its runtime would inherit an unmaintained dependency graph and a
  Python-centric, non-browser-native design.

Because Apache-2.0 licensing and enterprise adoption depend on clear
provenance, the project needs a durable, verifiable record that its
implementation was independently developed.

## Decision

1. **Agent Browser Shield is a product/design reference only.** No
   contributor may copy its source, port or translate its implementation,
   reproduce internal algorithms learned from its protected source, or
   submit code substantially derived from it. Public documentation and
   observable behavior may be used to understand the problem space.
2. **Requirements are implemented independently** from the OpenAgentFence
   PRD, published standards, public research, independent security
   reasoning, and permissively licensed references where appropriate.
3. **LLM Guard may be used under MIT terms**, but OpenAgentFence prefers
   independent, browser-agent-native implementations over inheriting the
   archived runtime. It is not a runtime dependency.
4. **Process controls:** contributors to scanner internals attest in
   `CONTRIBUTING.md` and the PR template that they have not read Agent
   Browser Shield source; changes to scanner internals carry a PR-template
   checkbox; ADRs and `docs/ARCHITECTURE.md` are maintained as the
   project's independent design record.
5. Where a public standard or research paper is the source of a technique,
   the implementation cites it in code comments or the package README.

## Consequences

- Positive: defensible provenance for Apache-2.0 distribution; a written
  design record that also helps reviewers and coding agents.
- Negative: some well-known heuristics must be rediscovered from first
  principles or public literature; slightly slower initial scanner work.
- Follow-up: keep this ADR referenced from `CONTRIBUTING.md`, `AGENTS.md`,
  and the PR template.

## Security impact

None on runtime behavior. Reduces legal and supply-chain risk to the project.
