---
"@openagentfence/core": minor
---

Correct deterministic aggregation and orchestration (PS-002): one absolute phase
deadline bounds all scanner work (with stricter per-scanner deadlines), and
timeout, parent cancellation, exception, and malformed results are distinguished
in types and trace output and never masquerade as `allow`. Parent cancellation
propagates promptly even for scanners that ignore their signal. Span-level
sanitization (`SanitizationSpan`) is applied sequentially in priority order with
removal winning overlaps. The risk aggregator's fixed precedence now runs
deterministic blocks, policy, secret, session restriction, deterministic
approval, semantic evidence, and heuristics in that order.
