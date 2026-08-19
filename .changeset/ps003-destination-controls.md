---
"@openagentfence/core": minor
"@openagentfence/policy": minor
"@openagentfence/scanners": minor
"@openagentfence/playwright": minor
---

Add the canonical deterministic destination boundary: HTTP(S)-only scheme
checks, origin allow/block/same-site evaluation, normalized private/local and
configured CIDR blocking, redirect-hop limits, and stable reasons. Add
cross-origin/SSRF scanner evidence and local corpus fixtures. Playwright can
opt into a route hook that aborts blocked initial navigations and fetches before
the target receives a request; redirect follow-up hops are explicitly
observed-only because the framework does not expose an abort hook for them.
