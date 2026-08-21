---
"@openagentfence/cli": minor
"@openagentfence/core": patch
---

Add the headless Playwright-backed `openagentfence test --corpus` security
regression command with stable reports, class filtering, and CI execution.
Completed sensitive-value sanitization now reports `ALLOW_SANITIZED` while
incomplete scans and egress violations remain fail closed.
