# ADR-0008: Policy loading stays outside `core`; the facade accepts a `PolicyEngine`

- **Status:** Accepted
- **Date:** 2026-08-15
- **Amended:** 2026-08-17
- **Related:** PRD §3, §13.15, §18.2; [ARCHITECTURE.md](../ARCHITECTURE.md) §3, §7, Q5; ADR-0002, ADR-0004

## Context

The PRD's vision example passes a file path to the facade
(`new OpenAgentFence({ policy: "./openagentfence.yml" })`). ARCHITECTURE §3
makes `@openagentfence/core` the dependency leaf: no YAML parser, no
JSON-Schema validator for the policy document, no policy profiles. Loading a
policy file therefore cannot happen inside `core` without either adding a
`core -> policy` edge (inverting the layering) or pulling YAML parsing — a
real attack surface — into the package that also holds the authorization
boundary.

## Decision

1. `@openagentfence/core`'s facade accepts **only a `PolicyEngine`**
   (`new OpenAgentFence({ policy?: PolicyEngine })`). When omitted, the
   built-in **secure-default engine** (PRD §13.6 capability defaults) is
   used. `core` never parses YAML/JSON policy files and never validates
   policy documents.
2. `@openagentfence/policy` owns the policy document type, its published JSON
   Schema, validation, and `loadPolicyDocument(pathOrDocument)`. This is the
   PS-001 boundary and returns only an immutable validated policy document; it
   does not return a `PolicyEngine` that ignores document rules. PS-002 owns
   deterministic evaluation, document-derived policy hashing,
   `createPolicyEngine(document)`, and the public
   `loadPolicy(pathOrDocument): Promise<PolicyEngine>`. The canonical usage,
   available after PS-002, is:

   ```typescript
   import { OpenAgentFence } from "@openagentfence/core";
   import { loadPolicy } from "@openagentfence/policy";

   const firewall = new OpenAgentFence({
     adapter,
     policy: await loadPolicy("./openagentfence.yml"),
   });
   ```

3. The one-line ergonomics the PRD wants (`policy: "./openagentfence.yml"`)
   are provided later by an **unscoped `openagentfence` meta-package** that
   re-exports the scoped packages and accepts a path string. It is not part
   of the v0.1 commitment; the npm name is reserved for it.
4. Documentation examples use form (2) until the meta-package exists.

## Options considered

- **`core` depends on `policy`.** Rejected: inverts the layering, drags a
  YAML parser and schema validator into the package holding the
  authorization boundary, and makes every `core` consumer pay for policy
  tooling.
- **Facade accepts a path and requires an injected loader.** Rejected: an
  awkward two-step API that still leaks file semantics into `core`.

## Consequences

- Positive: `core` stays dependency-light and reviewable; policy parsing is
  isolated where it can be fuzzed independently; the meta-package path keeps
  the desired ergonomics without compromising layering.
- Negative: two imports instead of one until the meta-package ships; the PRD
  §3 example is updated accordingly.
- Follow-up: OAF-CORE-009 implements the facade signature; OAF-POLICY-001
  implements `loadPolicyDocument`; OAF-POLICY-002 implements
  `createPolicyEngine` and `loadPolicy`; the meta-package is a post-v0.1 task.

## Security impact

Positive: keeps deserialization of untrusted-ish configuration (INV-16) out
of `core`; no change to authorization semantics.
