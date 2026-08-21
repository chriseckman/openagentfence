# OpenAgentFence

> An open-source security firewall for AI browser agents.

OpenAgentFence protects the trust boundary between **untrusted web content**
and **browser-agent capabilities**. A browser agent reads arbitrary pages and
then acts with authenticated sessions, credentials, files, and external
services. A page that can talk the agent into something can therefore reach
everything the agent can reach.

OpenAgentFence is middleware that sits between the browser, the agent/model,
sensitive data, and the browser action executor. It is built on one rule:

> **Detection informs security. Authorization enforces security.**

Prompt-injection detection is useful but probabilistic. So OpenAgentFence is
designed so that **even if the LLM is fooled by malicious page content,
deterministic controls still restrict what the agent can see, disclose, and
do** — what it may perceive, which actions it may execute, which origins it
may reach, where secrets may go, and what it may remember.

> **Status: pre-release.** M0-M6 P0 implementation is complete with local
> validation; M7-M8 verification and release work remains active. No packages
> are published yet, and nothing below should be
> read as production-ready. See [Status](#status).

---

## What it protects

Most guardrail libraries protect only the model boundary. OpenAgentFence
protects five boundaries:

```text
WEB     -> MODEL           what the agent is allowed to perceive
MODEL   -> ACTION          what the agent is allowed to do
ACTION  -> NETWORK         where the browser is allowed to go / send
DATA    -> SINK            where sensitive data is allowed to end up
MEMORY  -> FUTURE SESSION  what web-derived content may become "memory"
```

## Key capabilities

The table distinguishes locally implemented M0-M6 behavior from active and
deferred work. See [Status](#status) for release qualification.

| Area | Capability |
|------|------------|
| Perception | Browser prompt-injection defense: deterministic heuristics plus optional BYOK semantic classification |
| Perception | Hidden DOM and accessibility analysis: visibility classification, ARIA/DOM consistency, comments, metadata, attributes |
| Perception | Browser-content sanitization before content reaches the agent; encoded/obfuscated payload normalization |
| Action | Task-aware action authorization: a task contract compiled into an enforceable capability envelope; every high-impact action passes a deterministic Action Guard |
| Action | Origin and navigation controls: allowlist/blocklist, same-site, redirect-chain limits, private/local network and cloud-metadata blocking |
| Data | Secret isolation using **executor-side handles**: the model sees `<SECRET:name:id>`, never the value; values resolve only at approved sinks |
| Data | Sensitive-data and egress controls: destination-aware DLP for URLs, forms, uploads, and routed requests |
| Data | Provenance and taint tracking: web-derived data stays marked untrusted through transformation |
| Session | Session risk containment: `NORMAL -> RESTRICTED -> READ_ONLY -> QUARANTINED`, budgets against denial-of-wallet, approval gates |
| Memory | Minimum memory write/read guard: stored web content is scanned and integrity-bound, retains provenance, and re-enters only as tainted untrusted data |
| Operations | Local-first operation: deterministic scanners need no model, no cloud, no telemetry |
| Operations | BYOK guard models: OpenAI-compatible, Anthropic, Google, xAI, Ollama (local-first transport), or a custom callback; OpenCode 1.18.18 is a typed-unavailable optional surface |
| Integrations | Stagehand (first-class) and Playwright (independent) adapters; framework-neutral core |
| Audit | Redacted structured security traces with machine-readable reasons for every block; replay is planned as P1 |
| Testing | Local fixture server, adaptive-ready executable corpus, recorded Stagehand scenarios, offline Promptfoo comparison, reproducible property/invariant gates, and a pinned guarded-versus-unguarded benchmark runner; the full CLI and M8 measurement gates remain active |

## Status

| State | Items |
|-------|-------|
| **Available locally (M0-M6)** | Core contracts and traces; policy and deterministic Action Guard; Playwright/Stagehand fail-closed adapters; provenance carrier, taint floor, bounded coarse source-to-sink registry, and guarded memory write/read lifecycle; vault, secret scanning/resolution, DLP and Network Mutation Guard; offline-tested provider adapters, tier router, and opt-in BYOK scanner. Capability matrices identify enforced, observed-only, and unavailable surfaces. |
| **In development (M7-M8)** | Remaining adversarial corpus/invariant/benchmark gates, P0 CLI, API/docs freeze, and release hardening. See [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md). |
| **Required before v0.1** | M7-M8 P0 gates, current benchmark and false-positive evidence, complete release validation, and separately authorized/verifiable external publication. |
| **Deferred (v0.2+)** | Visual guard model and screenshot/DOM discrepancy detection or semantic matching, data-flow graph, signed receipts, network proxy, document parsing, enterprise DLP, reputation feeds, plugin marketplace, browser extension, hosted dashboard, Python SDK. |

There are no published benchmark results. The report format and offline smoke
runner are documented in [docs/benchmarks.md](docs/benchmarks.md). Any numbers that appear in the PRD
are illustrative targets, not measurements. Claims will be made only when
reproducible (pinned framework/model versions and corpus hash).

## Architecture overview

```text
                     Browser
                        |
                        v
                Perception Guard        <- DOM/ARIA/visibility scanners, sanitization,
                        |                  provenance labelling
                        v
                 Agent / Model          <- your agent, any framework, any model
                        |
                        v
                  Action Guard          <- normalize -> deterministic policy -> risk
                        |                  aggregation -> allow / sanitize / approve / block
                        v
             State Revalidation         <- bind observed state; mismatch invalidates authority
                        |
                        v
                Browser Executor        <- secret handles resolve here, only for bound sinks
                        |
                        v
          Egress / External Systems     <- origin, private-network, and DLP checks

   Parallel controls: Secret vault | Data-flow guard | Network Mutation Guard
                      Policy engine | Security trace
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Current API (pre-release)

The adapter packages own their secure wrappers; `core` remains framework
neutral and does not expose a framework-specific `firewall.wrap()` method.

```typescript
import { OpenAgentFence } from "@openagentfence/core";
import { chromium } from "playwright";
import { playwrightAdapter, wrapPage } from "@openagentfence/playwright";
import { loadPolicy } from "@openagentfence/policy";

const browser = await chromium.launch();
const page = await browser.newPage();
const firewall = new OpenAgentFence({
  adapter: playwrightAdapter(page),
  policy: await loadPolicy("./openagentfence.yml"),
});

const session = await firewall.start({
  task: "Find the lowest refundable hotel rate for these dates",
  capabilities: {
    navigation: "same-site",
    downloads: false,
    uploads: false,
    purchases: false,
    messaging: false,
    destructiveActions: false,
  },
});

session.on("finding", (f) => console.warn(f));
session.on("decision", (d) => console.log(d.verdict, d.reasons));

const secure = wrapPage(session, page);
await secure.goto("https://travel.example");

const trace = await session.end();
await browser.close();
```

Optional BYOK guard model (external network call, opt-in):

```typescript
import { guardProvider } from "@openagentfence/providers";

// Ollama is the local-first transport. The application selects a model;
// OpenAgentFence makes no model recommendation without measured evidence.
const firewall = new OpenAgentFence({
  adapter: playwrightAdapter(page),
  policy: await loadPolicy("./openagentfence.yml"),
  guardModel: guardProvider("ollama", { model: "<application-selected-model>" }),
});
```

`openagentfence.yml` contains authorization policy only. Applications that
enable a guard model construct it separately with
`@openagentfence/providers`; provider credentials remain in application setup
and the provider adapter and never enter policy or `core`.

## Design principles

- **Page content is never authority.** Web content may supply facts, never
  intent, permissions, policy, destinations, or approvals.
- **Authorization is deterministic.** Semantic classifiers produce evidence;
  they never solely permit a high-impact action, and a semantic "safe" cannot
  override a deterministic critical block.
- **Least privilege by task.** Every session gets a capability envelope
  derived from the task and application policy; it can only shrink.
- **Secrets are handles, not prompt text.** Values resolve executor-side,
  only for explicitly bound sinks.
- **Provenance travels with data.** Untrusted stays untrusted when copied,
  summarized, stored, or passed on.
- **Local first.** Deterministic protection works with no model and no
  network.
- **BYOK.** You choose the guard model and provider; none is required.
- **Fail closed at critical boundaries.** Timeouts, exhausted budgets, and
  missing approval handlers deny high-risk actions rather than allow them.
- **Explain every block.** Every decision carries stable, machine-readable
  reasons and redacted evidence.
- **Security must be measurable.** Attack fixtures, benchmarks, regression
  tests, and false-positive measurement ship with the project.

## Project scope

- **TypeScript / Node.js** (>= 20 LTS), ESM-first monorepo publishing
  `@openagentfence/*` packages: `core`, `stagehand`, `playwright`,
  `scanners`, `providers`, `policy`, `vault`, `testing`, `cli`.
- **Stagehand** is the first-class initial integration; **Playwright** is
  supported independently. Neither is a dependency of `core`.
- Plain Playwright applications can propose actions from any planner or from
  application code directly; using an agent framework is not required.
- **Framework-neutral and model-neutral core.** Adapters and providers are
  separate packages behind stable interfaces.
- **No required cloud service. No required telemetry.** Traces are local by
  default. Features that make external network calls (BYOK guard models,
  optional integrations) are documented as such.
- **Language-neutral contracts** (policy file, trace format, action
  taxonomy, corpus format) so other-language SDKs can follow later.

OpenAgentFence is in-process middleware, not an OS sandbox; see
[SECURITY.md](SECURITY.md) for the security model and what is out of scope.

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/browser-agent-firewall-prd.md](docs/browser-agent-firewall-prd.md) | Product requirements — what and why |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the system is divided: trust boundaries, packages, domain model, lifecycles |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, attackers, attack trees, security invariants, coverage and gaps |
| [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Milestones and dependency-aware tasks toward v0.1 |
| [docs/research-and-guidance.md](docs/research-and-guidance.md) | Non-normative research input and its disposition into the design |
| [docs/adr/](docs/adr/README.md) | Architecture decision records |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Workspace commands and package boundaries |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and security model |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor workflow, clean-room requirement, testing standards |
| [AGENTS.md](AGENTS.md) | Rules for autonomous coding agents working in this repository |
| [GOVERNANCE.md](GOVERNANCE.md) | How decisions are made and how maintainership will evolve |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |

## Security

Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not open public issues for exploitable
problems.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Note the mandatory clean-room
requirement: Agent Browser Shield is a design reference only and its
implementation must not be copied, ported, or translated.

## Design references

OpenAgentFence draws design inspiration from Agent Browser Shield, LLM Guard,
Invariant Guardrails, Pipelock, Promptfoo, PurpleLlama/LlamaFirewall, and
Stagehand (see [research and guidance](docs/research-and-guidance.md)). These are references and integration candidates
only. Their mention does not imply endorsement by, affiliation with, or code
reuse from those projects or their maintainers.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2026 Christopher Eckman.
