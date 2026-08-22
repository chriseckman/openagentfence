---
"@openagentfence/testing": minor
---

Pull forward the M2 fixture server and corpus contract (PS-010,
OAF-TEST-001/002). Add `startFixtureServer()` (loopback-only, multi-origin,
deterministic hidden-DOM/redirect/form-capture/download/popup/mutation routes),
`fixtureSentinel()`, a strict versioned corpus-case schema with
`validateCorpusCase`/`loadCorpusDocument`/`loadCorpusFile`/`corpusHash`
(bounded in bytes/depth/case-count; unknown, executable, and authority-mutating
metadata rejected), assertion helpers, and seed hidden-DOM attack/benign
fixtures under `security-corpus/`.
