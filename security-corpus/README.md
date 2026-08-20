# Security corpus

Adversarial and benign fixtures for OpenAgentFence v0.1 verification.

## Layout

- `corpus.json` — the corpus manifest (schema `1.0.0`), listing every case.
- `hidden-dom/` — hidden-DOM attack/benign HTML fixtures used by the M2
  vertical slice.
- `aria/`, `encoding/`, `navigation/`, and `benign/` â€” M2 scanner-closure
  fixtures; `exfiltration/` and `network-mutation/` hold targeted M4/M5
  control cases. M7 expands corpus breadth, adds the executable runner and
  benchmarks, and adds the remaining memory suites.

## Corpus-case format

A case is a strict, closed JSON object (see
`packages/testing/src/schemas/corpus-case.schema.json`). Required fields:
`id`, `mode` (`attack|benign`), `attackClasses` (A1–A20 ids), `invariants`
(INV-01…INV-21 ids), `kind` (`static|mutation|adaptive-ready`), `pages`
(`{ url, origin? }[]`), `task` (trusted task text), and `expected`
(`outcome` plus optional `reasons`/`findings`/`risk`/`control`). Optional:
`surfaces`, `initiator`, `policy`, `steps`, `locale`, `tags`.

Rules:

- Fixtures use **synthetic values only**; never embed real key/token patterns.
- No unknown fields, and no `exec`/`code`/`script`/`generator`/`require`/
  `import`/`grant`/`override` keys anywhere — corpus files are treated as
  hostile input and cannot grant capability or modify policy at runtime.
- No outbound network; pages load from the loopback fixture server.

## Execution

`@openagentfence/testing` provides `loadCorpusFile`/`corpusHash`; the
`openagentfence test --corpus` CLI gate lands with OAF-TEST-012 (M7).
