# ADR-0010: State-bound authorization and pre-execution revalidation

- **Status:** Accepted
- **Date:** 2026-08-15 (Accepted 2026-08-16)
- **Related:** PRD §7.11, §13.7, §13.9, §16; [ARCHITECTURE.md](../ARCHITECTURE.md) §4, §5, §8–9; INV-08, INV-19, INV-21; TB2, TB4, TB5, TB6

## Context

Authorization is unsafe if the executor performs an operation other than the
one the Action Guard inspected. This includes both an adapter asking a model to
infer a fresh action after authorizing a candidate and a page changing the
authorized target, destination, frame, origin, form action, visibility, or
other security-relevant state between observation and execution.

The first case is already prohibited by ADR-0002 and INV-08: Stagehand must
execute the exact authorized structured action or fail closed. This ADR does
not make that defect conditional on a new decision. It addresses the remaining
time-of-check/time-of-use boundary shared by all browser adapters.

## Decision

1. Authorization follows `observe -> normalize -> authorize structured action
   -> bind observed state -> re-resolve/revalidate -> execute that exact
   action`.
2. `ActionIntent` is a framework-neutral snapshot binding a canonical action
   to the page/context id, observation revision, target identity, frame and
   origin, destination or form action, security-relevant target attributes,
   visibility, policy hash, creation time, and expiry.
3. Successful authorization produces a branded `AuthorizedAction` containing
   the sanitized action and its `ActionIntent`. Browser executors accept only
   this type through the guarded path; a raw `CanonicalAction` is insufficient.
4. Immediately before execution, the adapter re-resolves the target and
   compares current security-relevant state with the bound intent. The
   comparison is deterministic and framework-specific only at the adapter
   edge.
5. A mismatch invalidates the authorization. The system reobserves and runs
   normalization and authorization again, subject to session budgets, or
   fails closed. It never patches or broadens the stale authorization.
6. The exact structured framework operation carried by the authorized action
   is executed. A fresh natural-language inference after authorization is
   prohibited.
7. Security-sensitive network mutations may carry the originating
   `actionIntentId` when correlation is available. Missing correlation never
   causes page-originated traffic to inherit an action's authorization.
8. Revalidation failures, retries, and state mismatches are recorded with
   stable reason codes and redacted state hashes.

## Options considered

- **Authorize a natural-language instruction and let the framework infer at
  execution.** Rejected because the executed operation can differ from the
  authorized candidate.
- **Patch the old authorization when state changes.** Rejected because a
  partial comparison can preserve stale assumptions. Reobservation and full
  reauthorization provide a single reviewable path.
- **Post-action detection only.** Rejected for irreversible side effects;
  detection after execution cannot restore atomicity.

## Consequences

- Positive: authorization is bound to both the operation and the page state
  inspected by the firewall.
- Positive: Stagehand, Playwright, and future adapters share one state-binding
  contract while retaining framework-specific resolution code.
- Cost: adapters must expose stable page, observation, and target identities
  and perform one bounded validation immediately before execution.
- Cost: rapidly changing pages may require reobservation or fail closed more
  often; budgets bound retries.
- Follow-up: add mutation/TOCTOU corpus cases and conformance tests for target,
  destination, form-action, frame, origin, visibility, and detached-node
  changes.

## Security impact

Strengthens INV-08 and establishes INV-19. It also provides the correlation
identifier used by INV-21 without treating correlation as authorization. The
existing Stagehand authorize-A/execute-B defect remains a vulnerability under
ADR-0002 independent of this decision.

## References

- [Atomicity for Agents: Exposing, Exploiting, and Mitigating TOCTOU Vulnerabilities in Browser-Use Agents](https://arxiv.org/abs/2603.00476)
- [ADR-0002](0002-framework-neutral-core-with-adapters.md)
- [ADR-0003](0003-deterministic-authorization-is-final-boundary.md)
