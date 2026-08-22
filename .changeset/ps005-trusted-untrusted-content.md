---
"@openagentfence/core": minor
---

Implement the trusted-intent and untrusted-content isolation boundary
(PS-005, OAF-CORE-016). `TrustedIntentContext` is an allowlisted, deeply frozen,
branded context for future intent criticism; `buildTrustedIntentContext` and
`validateTrustedIntentContext` reject raw strings, page observations,
screenshots, manifests, decoded payloads, arbitrary metadata, unsafe provenance
(web/tool/memory), oversized fields, and unknown keys. `UntrustedContent`
wraps sanitized page/tool/memory content with original provenance, a content
hash, revision/truncation metadata, and a type-level `instructionEligible:
false` that can never be set. Both contracts publish closed JSON Schemas
(`trusted-intent-context.schema.json`, `untrusted-content.schema.json`). No
semantic critic or provider/model call is added.
