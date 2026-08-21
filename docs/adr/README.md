# Architecture Decision Records

This directory holds the Architecture Decision Records (ADRs) for OpenAgentFence.
ADRs are the project's durable record of *why* the system is shaped the way it is.
They also serve a second purpose specific to this project: together with the
[PRD](../browser-agent-firewall-prd.md) and [ARCHITECTURE.md](../ARCHITECTURE.md),
they form the independent design record that supports the clean-room posture
described in [CONTRIBUTING.md](../../CONTRIBUTING.md) and
[ADR 0006](0006-clean-room-implementation-policy.md).

## When an ADR is required

Create (or propose) an ADR for any decision that materially changes architecture
or security posture. Non-exhaustive examples:

- Changing the scanner contract (`SecurityScanner`, `ScanResult`, `Finding`, phases).
- Changing policy semantics, verdict precedence, or fail-open/fail-closed behavior.
- Changing the canonical action taxonomy or capability envelope semantics.
- Changing secret trust boundaries (where raw values may exist, how handles resolve).
- Changing taint/provenance semantics.
- Changing adapter boundaries (what `core` may know about Stagehand/Playwright).
- Adding a required cloud dependency, required telemetry, or a required model vendor.
- Introducing a new runtime language or a native module.
- Adding a dependency to a security-critical path (`core`, `policy`, `vault`, decoders).
- Weakening any deterministic control, even temporarily.
- Changing the public project identity (package scope, CLI name, config filename).

Small implementation choices that do not change a boundary or a guarantee do not
need an ADR; document them in code comments or the relevant package README.

## Format

ADRs use a light MADR-style format. Copy [`0000-template.md`](0000-template.md).
Required sections: **Status**, **Context**, **Decision**, **Consequences**.
Optional: **Options considered**, **Security impact**, **References**.

Keep ADRs short and specific. An ADR records a decision, not a design document;
put detailed design in `docs/ARCHITECTURE.md` and link to it.

## Numbering and naming

- Files are named `NNNN-short-kebab-title.md` with a zero-padded four-digit number.
- Numbers are allocated sequentially and never reused, even for rejected ADRs.
- `0000` is reserved for the template.

## Status values

| Status | Meaning |
|--------|---------|
| `Proposed` | Under discussion; not yet binding. Agents and contributors may reference it but must not treat it as settled. |
| `Accepted` | Binding. Implementation must conform. |
| `Deprecated` | No longer recommended, but not replaced by a specific ADR. |
| `Superseded` | Replaced by a later ADR. The header must name the superseding ADR (`Superseded by ADR-00NN`). |
| `Rejected` | Considered and declined. Kept so the reasoning is not lost. |

## Superseding an ADR

1. Write the new ADR with status `Accepted` and a `Supersedes: ADR-00NN` line.
2. Change the old ADR's status to `Superseded by ADR-00MM`. Do not delete or
   rewrite the old ADR's body; history is the point.
3. Update any document that cited the old decision.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-typescript-first-architecture.md) | TypeScript-first architecture | Accepted |
| [0002](0002-framework-neutral-core-with-adapters.md) | Framework-neutral core with Stagehand and Playwright adapters | Accepted |
| [0003](0003-deterministic-authorization-is-final-boundary.md) | Deterministic authorization is the final security boundary | Accepted |
| [0004](0004-local-first-byok-semantic-classification.md) | Local-first and BYOK semantic classification | Accepted |
| [0005](0005-executor-side-secret-handles.md) | Executor-side secret handles | Accepted |
| [0006](0006-clean-room-implementation-policy.md) | Clean-room implementation policy | Accepted |
| [0007](0007-project-identity-and-package-namespace.md) | OpenAgentFence project identity and package namespace | Accepted |
| [0008](0008-policy-loading-and-facade-boundary.md) | Policy loading stays outside `core`; the facade accepts a `PolicyEngine` | Accepted |
| [0009](0009-application-owned-provider-runtime-configuration.md) | Guard-provider runtime configuration stays application-owned | Accepted |
| [0010](0010-state-bound-authorization-and-pre-execution-revalidation.md) | State-bound authorization and pre-execution revalidation | Accepted |
| [0012](0012-policy-parser-and-engine-handoff.md) | Policy parser approval and staged engine handoff | Accepted |
| [0013](0013-policy-runtime-state-and-suppression-trace.md) | Policy runtime state and suppression trace boundary | Accepted |
| [0014](0014-decoder-timeout-accounting.md) | Decoder timeout accounting | Accepted |
| [0017](0017-provenance-carrier-contract.md) | Provenance carrier contract | Accepted |
| [0018](0018-cli-playwright-corpus-execution-boundary.md) | CLI composition boundary for Playwright corpus execution | Proposed |

Add a row here whenever an ADR is created or its status changes.
