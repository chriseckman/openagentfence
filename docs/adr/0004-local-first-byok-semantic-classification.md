# ADR-0004: Local-first and BYOK semantic classification

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §3, §7.6, §7.7, §13.3, §13.16, §20, §34 (Decision 4); [ARCHITECTURE.md](../ARCHITECTURE.md) § Performance architecture

## Context

Browser-agent security middleware sees page content, credentials in handle
form, and user tasks. Requiring a hosted service, telemetry, or a specific
model vendor would create a new exfiltration path and limit adoption by
teams with data-residency constraints. At the same time, semantic
classification is valuable, and the primary agent model should not double as
the guard by default.

## Decision

1. **No mandatory cloud service.** OpenAgentFence runs entirely locally with
   deterministic scanners when no guard model is configured. Deterministic
   scanners must remain useful with zero models configured.
2. **No mandatory telemetry, analytics, or account.** Traces are stored
   locally by default; retention is controlled by the application.
3. **BYOK, provider-neutral semantic guard.** Semantic classification goes
   through the `GuardModelProvider` interface. Provider adapters
   (OpenAI-compatible HTTP, Anthropic, Google/Gemini, xAI, OpenCode,
   Ollama/local, custom callback) live in `@openagentfence/providers`;
   `core` bundles no model and no vendor SDK. Adding a provider requires no
   `core` change.
4. **Separate guard-model roles.** Configuration supports distinct models
   for the primary agent, text injection classification, visual injection
   classification (deferred to v0.2), and task alignment. The primary agent
   model is not reused as the sole guard by default.
5. **External network calls are opt-in and documented.** Every feature that
   makes an external call is flagged in documentation. Semantic classifiers
   are disabled unless configured.
6. **Cheap-first routing.** Deterministic rules run before browser
   heuristics, before a local classifier, before a BYOK model, before an
   optional second opinion. Semantic calls should be avoidable for most
   benign page elements.
7. **Structured guard output only.** Guard-model responses are validated
   against a schema; free-text output is never interpreted as a decision.

## Consequences

- Positive: usable in air-gapped and regulated environments; no vendor
  lock-in; guard-model compromise cannot silently expand agent capability
  (see ADR-0003).
- Negative: out-of-box detection quality varies with the configured
  provider; Ollama is the default local provider, but documentation cannot
  name a recommended model until corpus measurements make that choice
  reproducible (PRD v0.8 §13.16).
- Follow-up: select and document the recommended local model from corpus
  measurements; keep the application-owned provider factory surface uniform
  (factory by name). Runtime configuration and credentials follow
  [ADR-0009](0009-application-owned-provider-runtime-configuration.md).

## Security impact

Reduces the attack surface (no required third-party data path) and keeps the
guard model outside the authorization boundary. Guard-model provider code
must treat responses as untrusted input.
