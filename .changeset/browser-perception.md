---
"@openagentfence/scanners": minor
"@openagentfence/playwright": minor
"@openagentfence/stagehand": minor
---

Implement M2 browser perception and adapters: the deterministic PERCEPTION
scanner catalog (DOM visibility classifier, hidden-DOM, ARIA consistency,
comment/attribute/metadata, encoded-payload normalizer, Unicode-invisible,
prompt-injection heuristics, and suspicious-link scanners), the Playwright
adapter and secure `goto` wrapper, a structural Stagehand adapter and
observe→normalize→authorize wrapper, and the hidden-DOM vertical-slice
integration test. The Stagehand wrapper now validates the v4 response and
executes the exact authorized structured action instead of performing a fresh
natural-language inference; malformed or ambiguous candidates fail closed.
Stagehand 4.0.1 is pinned for development conformance and the supported peer
range is v4-only. `core` gains the extended in-page probe and a minimal
perceive/authorize session pipeline.
