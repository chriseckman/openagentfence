# ADR-0003: Deterministic authorization is the final security boundary

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §1, §7.2, §7.8, §8.4, §13.7, §15, §39; [THREAT_MODEL.md](../THREAT_MODEL.md) § Security invariants

## Context

Prompt-injection detection - heuristic or model-based - is probabilistic and
will eventually be fooled. The PRD's core proposition is that *even when the
agent or the classifier is fooled*, deterministic controls constrain what the
agent can see, disclose, and do: "Detection informs security. Authorization
enforces security."

## Decision

1. **Semantic classifiers produce evidence, not authorization.** Guard-model
   output is recorded as `Finding`s and may raise risk, trigger restricted
   mode, or add reasons to a decision. It is never the sole mechanism that
   permits or denies a high-impact action.
2. **Every high-impact action passes the deterministic Action Guard**, which
   evaluates the task contract / capability envelope, current and destination
   origin, provenance, session risk state, secret involvement, and
   side-effect class against policy.
3. **A semantic "safe" verdict cannot override a deterministic critical
   block.** Verdict precedence is fixed as: critical deterministic policy
   block, then explicit application policy, then secret/data-flow block, then
   session restriction, then semantic detection, then warning-only
   heuristics.
4. **Every attack class must have at least one deterministic control.** A
   class covered only by a probabilistic control is a tracked design
   deficiency, not an accepted state.
5. **Fail closed at critical boundaries.** Scanner timeout, guard-model
   failure, budget exhaustion, or an unregistered approval handler must not
   allow a high-risk action to proceed; the documented behavior is block or
   require-approval (which resolves to deny when no handler exists).
6. **Page content can never grant capability**, satisfy an approval, or
   relax policy. Only the application (through the task contract, policy,
   or a registered approval handler) can widen what the agent may do.

## Options considered

- **LLM-as-judge for authorization.** Rejected: the judge is subject to the
  same manipulation as the agent and adds latency/cost to every action.
- **Ensembles as the boundary.** Rejected as a *replacement*; permitted as an
  additional evidence source (PRD §13.3 P1) that still cannot override a
  deterministic critical block.

## Erratum (2026-08-15)

The options note previously ended with "unless explicitly configured." That
phrase contradicted Decision 3 and INV-03 and was removed. This correction does
not change the accepted decision: configuration cannot permit a semantic
verdict, including an ensemble result, to override a deterministic critical
block.

## Consequences

- Positive: security guarantees are testable with deterministic fixtures;
  the security corpus can assert exact outcomes.
- Negative: deterministic policy can produce false positives; the project
  mitigates with restricted mode, per-rule thresholds, auditable
  suppressions, and explanations rather than by weakening the boundary.
- Follow-up: every deterministic control needs a regression fixture; the
  aggregation precedence needs property-based tests.

## Security impact

This is the central security invariant. Any change to items 2-6 requires a
superseding ADR.
