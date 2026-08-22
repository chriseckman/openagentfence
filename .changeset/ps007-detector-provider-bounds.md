---
"@openagentfence/core": minor
---

Backfill detector tiers and bounded guard-provider execution (PS-007,
OAF-CORE-018). Add Tier 0/1/2 detector types with validated tier/kind
combinations (`defineScanner` resolves and rejects invalid pairings), and a
`GuardExecutionConstraints` contract (AbortSignal, absolute deadline,
input/output byte and token bounds, remaining call/token budgets).
`GuardModelProvider.classify` now returns `unknown` and is invoked only through
`runGuardProvider`, which schema-validates output and maps malformed,
false-safe, oversized, late, cancelled, throwing, and signal-ignoring providers
to typed fail-closed outcomes (`timeout`/`cancelled`/`exception`/`malformed`/
`oversized`/`budget_exhausted`) — never an accidental allow. Optional provider
limits are added to `ResourceLimits`. No provider credential, option, or vendor
SDK enters core.
