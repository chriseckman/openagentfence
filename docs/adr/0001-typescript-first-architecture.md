# ADR-0001: TypeScript-first architecture

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §29.1, §29.9, §34 (Decision 2); [ARCHITECTURE.md](../ARCHITECTURE.md) § Package boundaries

## Context

OpenAgentFence must integrate directly with browser-agent frameworks whose
primary SDKs are TypeScript/Node.js (Stagehand, Playwright for Node). It also
must be easy to adopt "like an observability SDK" (PRD §3). At the same time,
a large share of the browser-agent ecosystem is Python-first, and the PRD
commits to a Python distribution after the MVP (PRD §29.9). Two independently
maintained security engines would drift, and drift in a security product is a
vulnerability.

## Decision

1. The primary implementation of OpenAgentFence is **TypeScript on Node.js**
   (Node >= 20 LTS, TypeScript 5.x with `strict`, `noUncheckedIndexedAccess`,
   and `exactOptionalPropertyTypes`).
2. Packages are **ESM-first**. CJS compatibility builds are added only if
   adoption demonstrably requires them.
3. All cross-language contracts - the policy file, trace and receipt formats,
   the canonical action taxonomy, the plugin manifest, and the security-corpus
   format - are specified as **language-neutral formats** (YAML/JSON with
   published, versioned schemas), not merely as TypeScript types.
4. A Python package is a committed post-MVP target delivered first as a
   **sidecar** (thin Python client driving the Node engine over local RPC),
   and only later, if demand and measured need warrant it, as a **native
   Rust core** bound to Node and Python. A separately hand-maintained Python
   port is rejected.
5. Native modules (Rust or otherwise) may be introduced in the TypeScript
   engine only when justified by measured performance or security need, and
   only through a new ADR.

## Options considered

- **Python-first.** Rejected for v0.x: the initial integrations (Stagehand,
  Playwright/Node) and the "drop-in middleware" developer experience are
  Node-centric.
- **Dual TypeScript + Python implementations.** Rejected: divergent security
  behavior between engines is unacceptable.
- **Rust core from day one.** Rejected: slows delivery of the MVP without a
  demonstrated need; kept as an option gated on the measurable trigger
  criteria recorded in PRD v0.7 §34.

## Consequences

- Positive: fastest path to Stagehand/Playwright integration; single security
  engine; strong typing for public APIs.
- Negative: Python users depend on Node being present until/unless a native
  core exists.
- Follow-up: the Rust-core trigger criteria are resolved in PRD v0.7 §34;
  keep language-neutral schemas versioned from the first release and revisit
  the criteria only after v0.1.

## Security impact

Neutral to positive. A single engine keeps security semantics consistent
across front-ends. Language-neutral formats mean traces and policies remain
verifiable outside the TypeScript runtime.
