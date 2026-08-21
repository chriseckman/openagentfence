# Policies

The complete v0.1 key/default/effect table is in
[policy reference](policy-reference.md). In particular, scanner patterns and
threshold/suppression helper lookups require explicit application integration;
reserved `scanners.*.enabled` and `risk.*` fields do not reconfigure the default
catalog or session risk thresholds in v0.1. P1 policy profiles are unavailable.

`openagentfence.yml` is an authorization-only, versioned YAML or JSON document.
Its version-1 schema is published at
[`packages/policy/schemas/openagentfence-policy.schema.json`](../packages/policy/schemas/openagentfence-policy.schema.json).

Applications may load and validate the immutable document with
`loadPolicyDocument()`, construct a pure deterministic engine with
`createPolicyEngine(document)`, or use `loadPolicy()` for both operations.
The engine hash is canonical and stable across YAML/JSON key order.

```ts
import { createPolicyEngine, loadPolicyDocument } from "@openagentfence/policy";

const document = await loadPolicyDocument("./openagentfence.yml");
const policy = createPolicyEngine(document);
```

The package includes a runnable loader-only example:

```text
pnpm --filter @openagentfence/policy build
node packages/policy/examples/explicit-policy.mjs
```

## Safety boundary

The loader limits input to 1 MiB, 16 nesting levels, and 1,000 parsed nodes.
It rejects duplicate/non-string keys, aliases and anchors, merge keys, explicit
or custom tags, YAML directives, unknown properties, unsafe object keys,
environment-substitution syntax, provider/model settings, and credentials.
Errors identify only a bounded policy path; they do not reproduce document
content or values.

Policy files control authorization only. They cannot declare `guard_model`,
provider endpoint/model settings, API keys, or environment expansion. Those
remain application-owned under ADR-0009.

## Destination controls

`navigation.mode` narrows navigation to `same-origin`, `same-site`, an explicit
contract allowlist, or `none`. Contract `origins.block` always wins over an
allowlist. HTTP(S) is the only guarded navigation scheme: `javascript:`,
`data:`, `blob:`, `file:`, `vbscript:`, and custom schemes receive the stable
`unsupported_url_scheme` reason.

`navigation.max_redirect_hops` may lower the fixed limit of five hops. The
optional `navigation.internal_network_ranges` is a bounded list of CIDR ranges
that are always denied before an enforceable routed request continues. These
settings only narrow the capability envelope. DNS-rebinding detection remains
P1 because it needs resolved-address mediation, not hostname parsing.

Private/local destinations (loopback, RFC1918, link-local, metadata hosts,
normalized decimal/octal/hex IPv4 forms, and mapped IPv6 forms) are denied by
default. An application contract can request private-network access, but a
policy `block_private_networks: true` or an internal range still overrides it.

Browser network effects are evaluated independently from action authorization.
For the opt-in Playwright route boundary, initial navigation and fetch/XHR must
pass actual-origin, destination, private/internal-network, risk, and DLP checks
before continuation. ActionIntent correlation is evidence only. Redirect
follow-ups, forms, beacons, headers as an independent surface, WebSockets,
workers/service workers, uploads/downloads, popups, WebMCP, and Stagehand
traffic retain the adapter's exact `observed_only` or `unavailable` status;
policy cannot promote a missing framework hook into enforcement.

## Secret resolution

Task-contract secret bindings are trusted application data. Each names the
handle kind and exact canonical origins/field types; an optional selector and
form-action URL narrow the sink further. Core resolves only a handle present in
the exact, revalidated authorized operation, and only inside its one-shot
executor scope. Handles in unbound URLs, messages, files, memory, or other
sinks remain inert.

`secrets.restricted_mode` defaults to `keep_approved_sinks`: after the session
becomes RESTRICTED, only an exact sink that completed successfully while NORMAL
can be reused. `deny_all` disables even those sinks. READ_ONLY and QUARANTINED
always deny resolution. This setting can narrow resolution but cannot create a
binding, add an origin, bypass the credential capability, or expose a value.

## Runtime facts, thresholds, and suppressions

ADR-0013 supplies the engine with an immutable, firewall-owned runtime summary:
budget counters and deterministic scanner rule identifiers/severity only. It
never carries page content, raw findings, secrets, provider settings, or
semantic allow output. The engine is therefore synchronous and replayable.

`scanners.<scanner>.rules.<rule>` may set a `threshold` from 0 to 1 and a
`mode` of `warn` or `block`, with an optional exact-origin override. Typed
lookups require firewall-owned scanner/rule/origin metadata. Suppressions need
a rule, scope, and justification; an optional expiry must be a future
ISO-compatible timestamp when the document is loaded. They apply only to
deterministic scanner findings. Final capability, private-network, secret-sink,
ActionIntent, and network-mutation controls cannot be suppressed. Policy traces
record only matched rule IDs and applied suppression rule/scope/justification
references.

Stable decision explanations are listed in [reason codes](reason-codes.md).
