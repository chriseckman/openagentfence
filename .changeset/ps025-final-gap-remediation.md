---
"@openagentfence/cli": patch
"@openagentfence/core": patch
"@openagentfence/playwright": patch
"@openagentfence/policy": patch
"@openagentfence/providers": patch
"@openagentfence/scanners": patch
"@openagentfence/stagehand": patch
"@openagentfence/testing": patch
"@openagentfence/vault": patch
---

Harden the v0.1 release boundary: audit exact internal tarball dependency
versions, prove normal offline consumer installation, restrict the local
Promptfoo check to an explicit no-credential environment, fail closed on DCO
range resolution, and update the development test toolchain to remove known
advisories.
