---
"@openagentfence/core": patch
"@openagentfence/playwright": patch
---

Add bounded deterministic post-action comparison for unexpected navigation,
popup, download, and origin effects. Missing observation capability now records
an explicit restrictive outcome rather than a clean result.
