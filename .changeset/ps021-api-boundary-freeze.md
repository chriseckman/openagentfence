---
"@openagentfence/core": minor
"@openagentfence/vault": minor
"@openagentfence/playwright": minor
---

Freeze the v0.1 experimental API boundary: root core no longer exports raw
vault lookup construction, handle minting, generic exact execution, or a
scanner-registry getter. Reference-vault lookup and adapter raw-page access now
require firewall-minted capabilities, and Stagehand uses an unsupported
adapter-only exact-execution bridge. Document every package root API as
experimental through v0.3.
