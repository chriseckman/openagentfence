# @openagentfence/testing

Fixture server, corpus loader, benchmark runner, and assertions.

**Implemented (M2, `OAF-TEST-001/002`):**

- `startFixtureServer()` — loopback-only (`127.0.0.1`), multi-origin HTTP
  fixture server serving deterministic hidden-DOM attack/benign pages,
  redirects, form/request capture and echo, downloads, popups, and mutation
  hooks. It performs no outbound network and closes cleanly.
- Corpus contract — `validateCorpusCase` / `loadCorpusDocument` /
  `loadCorpusFile` / `corpusHash` with a strict, versioned, adaptive-ready
  schema (`src/schemas/corpus-case.schema.json`). Loading is bounded in bytes,
  depth, and case count; unknown fields and executable/generator/authority
  metadata are rejected; cases are treated as hostile input.
- Assertion helpers — `expectNoRawSecret`, `hasFindingCategory`,
  `isBlockingVerdict`, `reasonsOf`.
- Seed hidden-DOM attack/benign fixtures in `security-corpus/` (with
  `security-corpus/corpus.json`).

See [security-corpus/README.md](../../security-corpus/README.md) for the
corpus-contribution format.

**Status: not yet published.** This package is part of the OpenAgentFence
v0.1 plan ([implementation plan](../../docs/IMPLEMENTATION_PLAN.md)); no API
is stable and nothing here is production-ready.
