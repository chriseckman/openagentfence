# Scanner catalog

`defaultScanners()` is the local P0 catalog. It contains deterministic Tier 0
scanners only; no model, provider endpoint, credential, or telemetry is needed.
Every scanner receives a manifest-scoped, read-only context. A scanner finding
is evidence: deterministic core checks retain final authority and semantic
output can never grant an action, sink, approval, or capability.

## Default catalog

| Scanner ID | Tier / phase | Inputs and disposition |
| --- | --- | --- |
| `secret-sensitive` | Tier 0; PERCEPTION, MODEL_OUTPUT, PERSISTENCE, EGRESS | Bounded fixed-prefix/assignment/private-key detection. Replaces sensitive spans before release and registers only a bounded fingerprint/source record. |
| `memory-write` | Tier 0; PERSISTENCE | Removes or marks instruction-like memory content. Required by `session.memory.guardWrite()`. |
| `encoded-payload` | Tier 0; PERCEPTION | Bounded Base64, hex, URL, entity, and Unicode-escape decoding followed by conservative folding. Exhaustion is non-clean evidence. |
| `unicode-invisible` | Tier 0; PERCEPTION | Detects invisible/control characters as warning evidence. |
| `hidden-dom` | Tier 0; PERCEPTION | Detects instruction-like hidden, clipped, offscreen, pseudo, and embedded-frame content and sanitizes it. |
| `aria` | Tier 0; PERCEPTION | Detects instruction-like ARIA labels and descriptions without making accessibility content authority. |
| `comments` | Tier 0; PERCEPTION | Detects instruction-like HTML comments. |
| `attributes` | Tier 0; PERCEPTION | Detects instruction-like bounded DOM attributes. |
| `metadata` | Tier 0; PERCEPTION | Detects instruction-like title, meta, JSON-LD, microdata, and `noscript` values. |
| `url` | Tier 0; PERCEPTION | Detects unsafe schemes, private-network links, and visible-text/href mismatches. Final routing checks are independent. |
| `cross-origin-navigation` | Tier 0; PRE_ACTION | Emits cross-origin navigation evidence. The Action Guard owns the final decision. |
| `local-network-ssrf` | Tier 0; PRE_ACTION | Emits SSRF/private-network evidence. The destination and network guards independently block supported effects. |
| `secret-exfiltration` | Tier 0; MODEL_OUTPUT, PRE_ACTION | Emits value-free registered/tainted cross-origin exfiltration evidence. It cannot suppress the fixed source-to-sink block. |
| `file-effect-integrity` | Tier 0; PRE_ACTION | Validates declared file-effect integrity before a supported action reaches an executor. |

All default scanners have no ambient network permission. Registered plugin
scanners receive only their declared data capabilities through the core scoped
view; this is an in-process data boundary, not a sandbox for arbitrary
application JavaScript. Remote scanner loading is unsupported.

## Rule packs and bounds

The included injection pack is English lexical matching plus
script-independent structural signals and bounded normalization. It does not
claim native-language instruction recall. Every decoder/scanner path has byte,
depth, match, and deadline limits; cancellation, malformed output, or limit
exhaustion becomes a typed non-clean result rather than a clean allow.

Applications may supply up to 32 validated fixed-prefix secret patterns through
`defaultScanners({ secretPatterns })`. To use policy-shaped patterns, explicitly
pass `secretPatternsFromPolicy(document.scanners?.<id>?.patterns ?? [])`.
`scanners.*.enabled` is reserved metadata and does not disable a default
deterministic scanner in v0.1.

## Optional Tier 2 BYOK scanner

`createByokInjectionScannerFactory()` is opt-in and runs only when the
application supplies both a guard provider to `OpenAgentFence` and the factory.
It sends at most eight selected 512-byte redacted excerpts and one 512-byte
redacted task summary through the session-owned, budgeted callback. It never
sends whole-page HTML, raw secrets, or a provider the authority to allow an
action. Malformed, late, cancelled, unavailable, or budget-exhausted output is
value-free `scanner_unavailable` evidence.

An Ollama transport is local-only; other built-in HTTP provider transports are
external only when the application opts in. See
[`@openagentfence/providers`](../packages/providers/README.md) for exact
transport behavior. The current local benchmark measures scanner control
latency, not provider efficacy or a recommended model; see
[benchmarks](benchmarks.md).
