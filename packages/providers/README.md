# @openagentfence/providers

Application-owned `GuardModelProvider` adapters and the `guardProvider()`
factory. Provider selection, endpoints, models, and credentials stay in
application setup; policy and `@openagentfence/core` receive only the returned
provider instance.

**Status: not yet published.** This package is part of the OpenAgentFence
v0.1 plan ([implementation plan](../../docs/IMPLEMENTATION_PLAN.md)); APIs are
experimental and nothing here is production-ready.

```ts
import { guardProvider } from "@openagentfence/providers";

const guard = guardProvider("custom", {
  model: "application-callback-v1",
  makesExternalCalls: false,
  callback: async (request, execution) => {
    // Return structured data only. Respect execution.signal and deadline.
    return classifyLocally(request, execution);
  },
});
```

The library never reads environment variables. An application may pass an API
key to a remote provider option, but that credential is transport
authentication only: it is not classification content, provider metadata,
policy, core state, findings, events, approvals, traces, or errors.

Provider output is untrusted and crosses the strict core schema before it can
become evidence. Malformed, oversized, late, cancelled, unavailable, or
budget-exhausted calls do not become an allow decision. Session-owned call and
token authority is reserved before dispatch and is not refunded after dispatch.
An explicitly configured fallback is charged as another dispatch and runs only
within the same deadline, bounds, redacted request, and remaining authority.

| Provider | External calls | Status |
| --- | --- | --- |
| Custom callback | Application-declared | Available |
| OpenAI-compatible | Yes | Available: non-streaming `/v1/chat/completions` Structured Outputs |
| Ollama | Host-local transport | Available: loopback non-streaming `/api/chat` JSON-schema output |
| OpenCode | No calls (disabled) | Typed unavailable (see below) |
| Anthropic | Yes | Available: Messages API `2023-06-01` structured output |
| Google/Gemini | Yes | Available: legacy v1beta `generateContent` structured output |
| xAI | Yes | Available: v1 Responses structured output |

Provider transports use built-in `fetch` and offline contract tests; the
package has no vendor SDK dependency. External calls are opt-in.

## OpenAI-compatible HTTP

```ts
const guard = guardProvider("openai-compatible", {
  model: "your-structured-output-capable-model",
  apiKey: applicationSecrets.openAIKey,
  baseUrl: "https://api.openai.com/v1",
});
```

This entry point implements the documented non-streaming Chat Completions
protocol: bearer authentication, `response_format.type = "json_schema"`, and
strict structured output. Refusals, incomplete completions, multiple choices,
HTTP failures, malformed JSON, and oversized responses are unavailable
evidence. HTTP is accepted only for loopback test/compatible endpoints; remote
endpoints require HTTPS. See the official
[Chat API reference](https://developers.openai.com/api/reference/resources/chat)
and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

## Ollama local-first HTTP

```ts
const guard = guardProvider("ollama", {
  model: "an-explicitly-installed-model-name",
  // Defaults to http://127.0.0.1:11434/api
});
```

The dedicated Ollama entry point is intentionally loopback-only and sends no
authentication. It uses `POST /api/chat`, a JSON Schema in `format`, and
`stream: false`; `done: false`, error objects, or NDJSON fail closed. Install
Ollama and explicitly install/select a model in application setup before using
the provider. Ollama is OpenAgentFence's local-first provider mode, but no
particular model is recommended and no performance claim is made until the
later reproducible security-corpus benchmark required by A-01.

The loopback transport reports `makesExternalCalls: false`. This describes the
OpenAgentFence-to-daemon hop only: an Ollama daemon can itself be configured to
use cloud models. Direct Ollama Cloud is not supported by this entry point
because official Ollama documentation currently says cloud structured outputs
are unavailable. See the official [chat API](https://docs.ollama.com/api/chat),
[structured-output guide](https://docs.ollama.com/capabilities/structured-outputs),
and [API versioning statement](https://docs.ollama.com/api/introduction).

## OpenCode optional entry point

The `opencode` factory name and `openCodeGuardProvider()` export are reserved but
fail at construction with `GuardProviderConstructionError` code
`provider_unavailable`. This is intentional, not a deferred runtime surprise.

The official OpenCode server and SDK documentation verified on 2026-08-19,
together with the installed SDK manifest, documents OpenCode SDK **1.18.18**,
a local OpenAPI server, SDK package `@opencode-ai/sdk`, configured model
selection, and session/message endpoints. The documented message call is an agent-session
surface with optional tools and does not establish a strictly tool-free,
strict-JSON, bounded classification and cancellation contract. Adapting it would risk granting agentic
capabilities to untrusted evidence. OpenAgentFence therefore applies D-03 and
does not import the SDK, inspect real OpenCode configuration, start a server,
or guess a safer wire format. Default imports and installation remain
OpenCode-free.

See the official [OpenCode server](https://opencode.ai/docs/server/) and
[SDK](https://opencode.ai/docs/sdk/) documentation. A future adapter may enable
this entry point only after an official versioned surface can disable tools and
bound structured output under the shared provider contract.

## Anthropic, Gemini, and xAI

All three vendor adapters are opt-in direct HTTPS transports. They require an
application-supplied API key and model id; model ids in snippets are examples,
not defaults or recommendations.

```ts
const anthropic = guardProvider("anthropic", {
  model: "your-structured-output-capable-claude-model",
  apiKey: applicationSecrets.anthropicKey,
});
const gemini = guardProvider("google", {
  model: "your-structured-output-capable-gemini-model",
  apiKey: applicationSecrets.geminiKey,
});
const xai = guardProvider("xai", {
  model: "your-structured-output-capable-grok-model",
  apiKey: applicationSecrets.xaiKey,
});
```

- Anthropic uses `POST /v1/messages`, `x-api-key`, mandatory
  `anthropic-version: 2023-06-01`, and the current GA
  `output_config.format` JSON-schema contract. Only a single text block with
  `stop_reason: end_turn` is accepted; refusals and truncation fail closed.
- Google uses the explicitly documented legacy
  `POST /v1beta/models/{model}:generateContent` REST surface with
  `x-goog-api-key` and the current nested
  `generationConfig.responseFormat.text` schema. Deprecated
  `responseSchema` is not emitted. Only one `STOP` text candidate is accepted;
  prompt/safety blocks and every other finish reason fail closed.
- xAI uses its recommended `POST /v1/responses` surface with bearer auth,
  `store: false`, no tools, and `text.format` strict JSON schema. Only one
  completed response message containing one `output_text` part is accepted.

Provider errors and rate-limit bodies are discarded, never retried
automatically, and never enter diagnostics. The shared deadline, cancellation,
byte, schema, call, and token boundaries apply identically. Protocol evidence
was verified on 2026-08-19 from the official
[Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create),
[Anthropic Structured Outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs),
[Gemini GenerateContent](https://ai.google.dev/api/generate-content),
[Gemini structured output](https://ai.google.dev/gemini-api/docs/generate-content/structured-output),
[xAI Responses comparison](https://docs.x.ai/developers/model-capabilities/text/comparison),
and [xAI Structured Outputs](https://docs.x.ai/developers/model-capabilities/text/structured-outputs)
documentation.
