# ADR-0009: Guard-provider runtime configuration stays application-owned

- **Status:** Accepted
- **Date:** 2026-08-15
- **Related:** PRD §3, §13.6, §13.15, §13.16, §18.2; [ARCHITECTURE.md](../ARCHITECTURE.md) §3, §7, §17; ADR-0004, ADR-0008; INV-05, INV-12, INV-16; TB1, TB3

## Context

Guard providers need runtime settings such as provider name, endpoint, model,
timeout, and sometimes a credential. The PRD previously placed those values in
a `guard_model` policy block, including environment substitution for an API
key. That conflicts with the policy package boundary: policy documents express
authorization rules, `@openagentfence/policy` may not receive secret values,
and `loadPolicy()` returns only a `PolicyEngine`. Passing the policy document
into `core` to recover runtime settings would also violate ADR-0008.

## Decision

1. For v0.1, `openagentfence.yml` is an authorization and security-policy
   document only. It contains no guard-provider runtime configuration and no
   provider credential or environment-variable reference.
2. The application owns guard-provider runtime configuration. It resolves its
   own environment variables or secret source and calls
   `guardProvider(name, options)` in `@openagentfence/providers`.
3. `@openagentfence/providers` owns provider-specific validation, transport,
   and authentication. A provider credential may exist only in application
   setup and the selected provider adapter. It must never enter `core`, a
   `PolicyEngine`, scanners, classification content, findings, events, approval
   requests, traces, or policy hashes.
4. `OpenAgentFence` receives an instantiated `GuardModelProvider`, not a
   provider name, provider options, policy document, or credential. Ollama
   remains the default local provider and ordinarily requires no credential.
5. `core` compiles the baseline `CapabilityEnvelope` from the validated
   `TaskContract` and secure defaults only. The `PolicyEngine` is a separate
   deterministic authorization input that may narrow the envelope or deny an
   action; neither `core` nor the envelope compiler receives the source policy
   document or a profile object.
6. A future declarative runtime loader, if added, must be a separate
   application-facing facility using opaque secret references. It must not add
   environment substitution to the policy loader or change the boundaries
   above without a new ADR.

The canonical v0.1 composition is:

```typescript
const policy = await loadPolicy("./openagentfence.yml");

const guardModel = guardProvider("openai", {
  apiKey: process.env.GUARD_API_KEY,
  model: process.env.GUARD_MODEL,
});

const firewall = new OpenAgentFence({
  adapter,
  policy,
  guardModel,
});
```

The application resolves both environment variables. Only the provider adapter
receives `GUARD_API_KEY`; the policy loader and `OpenAgentFence` receive neither
the credential nor the provider options.

## Options considered

- **Keep `guard_model` in the policy document.** Rejected: it mixes runtime
  transport concerns with authorization policy and invites credentials into
  policy parsing, hashing, validation errors, and traces.
- **Pass the policy document through the facade.** Rejected: violates ADR-0008
  and gives `core` document-loading responsibilities.
- **Have `core` construct providers.** Rejected: would add provider/network
  knowledge and possibly credentials to the dependency leaf.

## Consequences

- Positive: policy artifacts remain portable and non-secret; provider
  credentials have a narrow, auditable lifetime; `core` stays provider- and
  document-neutral.
- Negative: applications configure policy and the guard provider separately;
  switching providers is a factory-call change rather than a policy-file edit.
- Follow-up: OAF-POLICY-001 excludes `guard_model` and environment
  substitution; OAF-GUARD-001 implements the application-owned factory;
  OAF-CORE-004 and OAF-CORE-009 preserve the document-neutral boundary.

## Security impact

This narrows TB3 and prevents provider authentication secrets from crossing
TB1 into `core` or policy processing. Provider responses remain untrusted
semantic evidence and cannot weaken deterministic authorization.
