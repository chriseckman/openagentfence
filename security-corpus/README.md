# Security corpus

Adversarial and benign fixtures for offline OpenAgentFence verification.

## Layout and schema

`corpus.json` is the strict `1.1.0` manifest. Its cases reference fixture files
under this directory. The current 227 cases cover hidden DOM, ARIA, encoding,
attributes/metadata, navigation, redirects, SSRF, popups, high-impact
approvals, budgets, exfiltration, memory poisoning, network mutation, multilingual content,
benign look-alikes, resource limits, semantic-guard failure, ActionIntent
mutation, malicious WebMCP metadata, and independent network effects. Existing
cases and expected outcomes remain authoritative.

Every case requires:

- a stable lowercase-hyphenated `id`, `mode`, A1-A20 `attackClasses`, and
  INV-01-INV-21 `invariants`;
- `kind` (`static`, `mutation`, or `adaptive-ready`), bounded `surfaces`, an
  explicit `initiator`, and one or more local `pages`;
- a trusted `task`, optional closed task-contract/policy/steps data, and a
  closed `expected` outcome with optional reasons, findings, risk, and control;
- bounded declarative `mutation` metadata for mutation cases or inert
  `adaptive` seed/transform metadata for adaptive-ready cases.

The published contract is
[`corpus-case.schema.json`](../packages/testing/src/schemas/corpus-case.schema.json).
The runtime loader additionally enforces UTF-8 byte, nesting, fixture-size,
duplicate-ID, safe-path, and accessor/prototype bounds.

## Contribution rules

- Add attack and benign counterparts where applicable and cite the threat
  class, invariants, surfaces, and expected deterministic control.
- Use only synthetic values. The testing gate scans the complete corpus tree
  for common real credential/key formats.
- Keep fixtures deterministic and offline. They may address only loopback
  origins supplied by `startFixtureServer()`.
- Generator metadata is data only. It cannot alter task, policy, capability,
  or expected outcomes; generated candidates are never a required gate until
  reviewed and committed as static cases.
- Do not delete or weaken a failing fixture. Fix the implementation or record
  the owning prompt as blocked.

## Hashing and local execution

The corpus hash is SHA-256 over schema version, validated cases sorted by ID,
and referenced fixture SHA-256 digests sorted by normalized path. This pins
both metadata and page content while remaining independent of manifest order.

```text
pnpm --filter @openagentfence/testing test
pnpm --filter @openagentfence/playwright test:integration
```

The full `openagentfence test --corpus security-corpus/` command and required
CI regression gate land in OAF-TEST-012 later in M7.

## Current deterministic perception matrix

| Group | Attack | Benign | Resource limits | Browser assertions |
| --- | ---: | ---: | ---: | --- |
| Hidden DOM and ARIA | 21 | 6 | - | category, web provenance, sanitized exclusion, `RESTRICTED`, cross-origin follow-up block |
| Encoding, Unicode, attributes, and metadata | 20 | 4 | 2 | category, web provenance, sanitized exclusion, risk/assessment, bounded non-clean failure |
| Navigation, redirects, and schemes | 7 | 3 | 1 redirect limit | exact reasons, origin scope, redirect-chain bounds, observed-only hop evidence |
| SSRF and routed private-network access | 13 | 1 | - | literal/alternate/CIDR checks and zero-byte routed fetch; explicit private-network sibling |
| Popups and tabs | 4 | 1 | 1 tab limit | post-creation closure, risk inheritance, adapter trace, capability-gap evidence |
| High-impact approval and action budgets | 10 | 7 | 3 budget limits | deny without handler, configured approval, approval TOCTOU, trace-valid budget exhaustion |
| Secret and sensitive-data exfiltration | 22 | 4 | bounded D-11 forms | per-case zero attacker bytes, registry-aware artifact checks, exact bound/same-origin siblings, absent/fake-allow provider |
| Application-owned memory | 9 | 2 | closed schema and canonical hash | public write, JSON store, fresh-session read, provenance/data-only/taint checks, malformed/tampered denial, secret leak checks |
| Multilingual structural signals | 12 | - | English lexical pack remains explicit | four scripts including Arabic and Hebrew RTL; Unicode, encoding, hidden-DOM, ARIA, comment, and metadata outcomes |
| Realistic benign baseline | - | 30 | six page categories | zero deterministic `block`/`approve` recommendations, risk score zero, and no risk transition |
| A18 ActionIntent mutation | 10 | 1 | one-field plus combined races | all bound fields invalidate deterministically; live Playwright and recorded Stagehand effects remain zero |
| A19 compromised/failed guard | 6 | 1 | malformed, oversized, timeout, cancellation, and budget | typed bounded failure; false-safe evidence never grants authority; required failures stop side effects |
| A20 network/WebMCP mutation | 12 | 1 | exact capability ledger | routed fetch zero-byte block; observed-only and unavailable rows stay explicit; Stagehand WebMCP makes zero calls |

The totals include the original display-none, accessibility-only ARIA,
Base64, skip-link, and accessible-product seeds. The query-selected matrix
fixtures are committed deterministic `mutation` cases; their variant name is
inert metadata, and the fixture bytes are included in corpus hash
`a0ce0709c0d5e0fb43189558c8cbb2fc0da1dcafe71cf129f7f0da841327b536`.

The multilingual group exercises language-independent structure and bounded
normalization across Latin, Japanese, Arabic, and Hebrew pages. Mixed-language
English attack phrases are used where the deterministic lexical pack is
required. This is not a native-language recall claim: the built-in rule pack
is English, while native multilingual semantic classification remains an
explicit application-owned BYOK evidence surface. The benign baseline contains
five each of news, shopping, documentation, form, dashboard, and legitimate
hidden-UI pages; its measured default-policy hard-block rate is 0/30.

Playwright proves zero-byte prevention only for its measured enforced initial
navigation and routed-fetch hooks. Redirect follow-up requests are
`observed_only`, and popup events arrive after browser creation; those corpus
rows assert the explicit capability gap, containment/risk response, and trace
rather than claiming pre-request prevention. Stagehand popup/network surfaces
remain unavailable.

The exfiltration group uses only runtime-generated synthetic values; fixtures,
snapshots, and expected errors never contain a sentinel. Every attack checks
the attacker capture ledger before and after the proposed side effect and runs
`expectNoRawSecretIn` over decisions, events, findings/perception, provider
requests, errors, and traces that exist for that boundary. Approved exact-sink
and same-origin deliveries are intentionally excluded from leak-artifact scans
because they are the executor/network payload whose narrowly bound delivery is
being proven.

The memory group loads a real page candidate, calls the public
`session.memory.guardWrite()` API, serializes the resulting closed item through
an application-owned store, and calls `guardRead()` in a fresh session. Valid
items remain data-only, retain original provenance, and activate the web taint
floor. Malformed, relabelled, content-tampered, and provenance-tampered items
deny before release; runtime-only synthetic secret values are absent from the
stored JSON, findings, returns, errors, and both traces.

The Stagehand 4.0.1 offline recording suite links 24 adapter scenarios to
these committed cases without adding model-generated fixture data. Its closed
recording document covers exact structured action, one-field and multi-field
mutation, extraction, screenshot-first, malicious WebMCP manifest/schema/
annotations/result data, secret/file/form, disabled-path, and escape-hatch
behavior; unauthorized paths assert zero framework execution.
