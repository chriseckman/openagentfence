---
"@openagentfence/core": patch
"@openagentfence/playwright": patch
---

Close the M4 data-control gate with a sanitizer-composition safeguard that
prevents independent whole-text transforms from restoring span-redacted
values, plus a combined Playwright detection, vault, exact-sink, and zero-byte
blocked-egress regression.
