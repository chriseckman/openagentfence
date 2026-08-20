# @openagentfence/policy

Policy document model and bounded YAML/JSON loader. `loadPolicyDocument()`
returns a branded, deeply frozen version-1 authorization policy and rejects
unknown fields, provider/runtime configuration, credentials/environment
substitution, aliases, tags, duplicate keys, unsafe object keys, and oversized
or deeply nested input.

The published schema is `schemas/openagentfence-policy.schema.json`.
`createPolicyEngine()` produces the pure synchronous engine; `loadPolicy()`
loads and constructs it in one call. Runtime budgets and deterministic scanner
summaries are supplied through the validated core `PolicyRuntimeState` contract
(ADR-0013), never through mutable engine state or untrusted page content.

Navigation policy may additionally lower `max_redirect_hops` from the secure
five-hop limit and add up to 64 internal CIDR deny ranges. These are exposed to
the firewall as immutable `destinationRules`; they cannot widen a contract or
disable the core private-network default.

Scanner configuration may add bounded, data-only secret prefix patterns under
`scanners.secret.patterns`. Each entry declares an inert literal prefix,
alphabet, minimum/maximum total length, and optional handle kind. The loader
accepts at most 32 entries and rejects arbitrary regular expressions; provider
credentials and secret values do not belong in policy.

The sole direct parser dependency is `yaml@2.9.0`, pinned exactly under
ADR-0012. It supports Node 20 and built-in TypeScript declarations; the loader
uses strict parsing with string-key/duplicate-key checks, no aliases, no merge
keys, no custom or explicit tags, and application-level byte/depth/node bounds.

**Status: not yet published.** This package is part of the OpenAgentFence
v0.1 plan ([implementation plan](../../docs/IMPLEMENTATION_PLAN.md)); no API
is stable and nothing here is production-ready.
