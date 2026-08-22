---
"@openagentfence/core": minor
"@openagentfence/playwright": minor
---

Complete core observation, probe, and adapter conformance (PS-004). The in-page
probe now collects the full OAF-CORE-014 signal set — viewport position
(`inViewport`), font size, raw color/background (contrast ratio stays
out-of-page), `position`/`transform`/`clipPath`/`overflow`, pseudo-element text,
`noscript`, and SVG text — and enforces aggregate per-category limits (nodes,
per-field and total text, comments, metadata, links, time) reported as a
structured `truncation` record plus `truncated`; the probe is read-only and
versioned (`PROBE_VERSION` bumped to 2). Add `validateProbeResult` so probe
output (untrusted, TB2) crosses runtime validation before use, and a
framework-neutral `runAdapterConformance`/`validatePageObservation` suite.
`PageObservation`/capabilities are unchanged but conformance now proves them
truthful. The Playwright adapter validates probe output at `observe()` and a
real-browser integration test covers signals, truncation, non-mutation, and the
validation path.
