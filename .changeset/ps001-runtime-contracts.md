---
"@openagentfence/core": minor
---

Close the foundational runtime-contract boundaries (PS-001): `validateTaskContract`
now returns a deeply frozen `ValidatedTaskContract` that only the validator can
produce, and `compileTaskContract` accepts only that validated form — raw,
page-supplied, or structurally similar objects are rejected at compile time and
fail safely at runtime. Add runtime `validateFinding` and `validateScanResult`
validators (strict unknown-field rejection), a published
`scan-result.schema.json`, and tighten `finding.schema.json` to reject unknown
nested fields.
