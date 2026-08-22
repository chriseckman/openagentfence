---
"@openagentfence/core": minor
"@openagentfence/playwright": minor
---

Implement `ActionIntent` and branded `AuthorizedAction` (PS-008, OAF-CORE-015;
ADR-0010 accepted). Add a framework-neutral state-bound snapshot with
deterministic, property-order-independent fingerprints (`stableSerialize`,
`computeIntentFingerprint`) and stable mismatch codes
(`compareIntentState`), expiry (`isIntentExpired`), and strict
`validateActionIntent`. `mintAuthorizedAction` is the only constructor of the
branded authorization and validates the operation/policy hash against the
intent. `BrowserAdapter.executeAuthorized` now accepts only `AuthorizedAction`,
so a raw `CanonicalAction` is a compile-time error; `isAuthorizedAction`
rejects forged objects. Five state-binding reason codes
(`action_intent_mismatch`, `action_intent_expired`, `action_policy_mismatch`,
`action_operation_mismatch`, `action_intent_retry_exhausted`) and
`authorized_action`/`action_revalidation` trace events with redacted state
hashes are added, plus closed `action-intent.schema.json` and
`authorized-action.schema.json`. The Playwright adapter migrates to the new
executor contract.
