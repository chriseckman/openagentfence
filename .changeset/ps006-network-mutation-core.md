---
"@openagentfence/core": minor
---

Implement the Network Mutation Guard core contract (PS-006, OAF-CORE-017).
Add `NetworkMutation` with surface (`navigation`…`webmcp`) and initiator
(`authorized_action`…`unknown`) vocabularies, per-surface `enforced |
observed_only | unavailable` capability matrices (conservative default), a
`NetworkGuard`/`NetworkGuardDecision` contract with a stable reason set
(`unknown_network_initiator`, `network_enforcement_unavailable`,
`network_origin_not_allowed`, `network_metadata_oversized`,
`network_guard_failure`), bounded redacted request metadata (headers + body
hash/size, never raw values), and `validateNetworkMutation` /
`validateNetworkCapabilities`. A `network_mutation` trace event kind and a
closed `network-mutation.schema.json` are added. Correlation to an
`ActionIntent` is evidence only; no proxy or browser hook enters core.
