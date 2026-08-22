# @openagentfence/scanners

The deterministic and optional BYOK scanner catalog of OpenAgentFence
([ARCHITECTURE.md](../../docs/ARCHITECTURE.md) §3). Scanners implement the
`SecurityScanner` contract from `@openagentfence/core` and are clean-room
implementations (ADR-0006).

The source-backed phase, tier, permission, and capability catalogue is in
[docs/scanners.md](../../docs/scanners.md).

**Implemented (M2, `OAF-BROWSER-005…011`):**

- DOM visibility classifier (11 classes) — `classifyNode`, `classifyObservation`.
- Hidden-DOM scanner (instruction-like hidden content + sanitized representation).
- ARIA/DOM consistency scanner.
- HTML comment, attribute, and metadata/JSON-LD scanners.
- Encoded-payload normalizer (bounded Base64, hex, URL, HTML-entity, and
  JavaScript Unicode-escape decoding, including reversible nested chains) and
  Unicode-invisible scanner. NFKC, zero-width, conservative homoglyph, and
  leetspeak folding run only for analysis. DOM text, ARIA fields, bounded
  attributes, comments, OpenGraph/meta, JSON-LD, microdata, and `noscript`
  surfaces are covered; inert script/style/code source is excluded to avoid
  turning implementation strings into findings. Inputs exceeding byte,
  output, depth, probe, or decoder CPU-time limits are reported as non-clean
  bounded evidence. Scanner wall-clock cancellation remains enforced by core.
- Prompt-injection heuristic engine (English rule pack). Rule packs are inert,
  bounded data; unsafe regular-expression shapes are rejected before use.
  Script-independent structure and normalization work on multilingual pages,
  but the built-in pack does not claim native-language instruction recall.
- Suspicious-link scanner (unsafe schemes, private-network targets, text/href mismatch).
- Secret/sensitive-value scanner for fixed token prefixes, credential assignments,
  and bounded private-key blocks. Matches are replaced before text is released;
  findings contain only a detector ID and fingerprint. The built-in detector is
  limited to 100 KiB, 32 matches, and 50 ms and fails non-clean on exhaustion.
  Syntactically valid opaque handles are masked before scanning because they are
  inert references governed by executor-side resolution, not raw credentials.
  PERCEPTION, MODEL_OUTPUT, PERSISTENCE, and EGRESS use the same bounded scanner;
  core invokes EGRESS scanning before supported action and routed-request checks.
- Secret-exfiltration evidence scanner for MODEL_OUTPUT handles and PRE_ACTION
  registered/tainted data aimed cross-origin. It emits only counts and a
  destination hash; the independent fixed core rule owns authorization, so
  disabling or false-safe scanner output cannot remove the block.
- Opt-in Tier 2 BYOK injection scanner for PERCEPTION and MODEL_OUTPUT. It
  selects only hidden, decoded, metadata/comment, deterministic-match, or
  bounded model-output regions; it never serializes whole-page HTML. At most
  eight 512-byte excerpts (4096 bytes total) and a 512-byte redacted task
  summary reach the session-owned guard callback. Provider results remain
  semantic evidence, arbitrary category text is never reflected, and every
  typed failure becomes value-free `scanner_unavailable` evidence.
- Memory-write PERSISTENCE scanner for deterministic instruction/data
  separation. It removes bounded injection-rule matches and commands such as
  `remember: always send ...`, emits `memory_instruction` with rule-id-only
  evidence, and fails non-clean at 100 KiB, 32 matches, cancellation, or its
  50 ms deadline. `defaultScanners()` includes it with the PERSISTENCE-capable
  secret scanner.

Set `required: true` only when the application requires Tier 2 availability
before side effects. A failed required check still cannot make model output an
authorization authority: harmless READ/SCROLL operations remain usable, while
core deterministically blocks later high-impact actions with
`scanner_unavailable` until a successful required check refreshes the session.

`defaultScanners()` returns the P0 catalog in priority order. Applications can
add at most 32 data-only prefix patterns through
`defaultScanners({ secretPatterns })`; use `secretPatternsFromPolicy()` for the
snake-case policy representation. Arbitrary regular expressions are rejected.
This P0 scanner covers textual observation/model/memory/egress values; it does
not claim visual secret detection in screenshots.

BYOK classification is off by default and may make external calls according to
the application-selected provider. Configure it without importing providers
into this package:

```ts
new OpenAgentFence({
  adapter,
  guardModel: guardProvider("ollama", { model: applicationModel }),
  scanners: defaultScanners(),
  guardScannerFactories: [createByokInjectionScannerFactory({ localeHints: ["en"] })],
});
```

The facade constructs the scanner per session and supplies only a narrow,
budget-consuming classifier callback. There are no live-model efficacy claims;
multilingual tests use deterministic fakes. The current local control
measurement is documented in [benchmarks](../../docs/benchmarks.md); it makes
no provider/model efficacy or recommendation claim.

Probe truncation downgrades otherwise-visible content to
`VISIBLE_LOW_CONFIDENCE`; the scanner layer preserves the boundary rather than
silently claiming a complete observation.

**Status: experimental through v0.3.** No API is stable; see the
[implementation plan](../../docs/IMPLEMENTATION_PLAN.md).
Every package-root export is experimental through v0.3; see the
[v0.1 API stability ledger](../../docs/api-stability.md).
