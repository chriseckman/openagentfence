# @openagentfence/scanners

The deterministic (and, later, BYOK) scanner catalog of OpenAgentFence
([ARCHITECTURE.md](../../docs/ARCHITECTURE.md) §3). Scanners implement the
`SecurityScanner` contract from `@openagentfence/core` and are clean-room
implementations (ADR-0006).

**Implemented (M2, `OAF-BROWSER-005…011`):**

- DOM visibility classifier (11 classes) — `classifyNode`, `classifyObservation`.
- Hidden-DOM scanner (instruction-like hidden content + sanitized representation).
- ARIA/DOM consistency scanner.
- HTML comment, attribute, and metadata/JSON-LD scanners.
- Encoded-payload normalizer (bounded Base64/hex/URL/entity decoding) and
  Unicode-invisible scanner. Inputs exceeding byte, output, depth, or decoder
  CPU-time limits are reported as refused evidence and are never treated as
  clean. Scanner wall-clock cancellation remains enforced by core.
- Prompt-injection heuristic engine (English rule pack). Rule packs are inert,
  bounded data; unsafe regular-expression shapes are rejected before use.
- Suspicious-link scanner (unsafe schemes, private-network targets, text/href mismatch).

`defaultScanners()` returns the P0 PERCEPTION catalog in priority order.

Probe truncation downgrades otherwise-visible content to
`VISIBLE_LOW_CONFIDENCE`; the scanner layer preserves the boundary rather than
silently claiming a complete observation.

**Status: not yet published.** No API is stable; see the
[implementation plan](../../docs/IMPLEMENTATION_PLAN.md).
