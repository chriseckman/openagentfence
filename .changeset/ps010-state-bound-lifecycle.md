---
"@openagentfence/core": minor
"@openagentfence/playwright": minor
"@openagentfence/stagehand": minor
---

Bind issued actions to the firewall-owned policy, risk, budget, approval, and
session state and invalidate stale authority before any executor is invoked.
Playwright reobserves and fully reauthorizes once after deterministic state
invalidation. Stagehand now consumes the core-issued one-shot authorization
through a narrow exact-executor bridge, derives its operation hash from the
captured structured action, and records unavailable post-action observation
rather than retaining parallel executor authority.
