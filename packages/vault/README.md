# @openagentfence/vault

Reference in-memory vault and `VaultAdapter` implementations.

`inMemoryVault()` creates bounded, non-persistent, session-scoped storage.
Applications register a value through `SecuritySession.registerSecret()` and
receive only an opaque handle. The raw value is retained in memory until the
session expires or ends, then is invalidated. Core wraps the executor lookup in
a one-action resolver that checks the trusted sink binding, exact live intent,
capability envelope, policy, and risk state before vault access. Browser
substitution remains adapter-owned and occurs only at the final framework call.

**Status: not yet published.** This package is part of the OpenAgentFence
v0.1 plan ([implementation plan](../../docs/IMPLEMENTATION_PLAN.md)); no API
is stable and nothing here is production-ready.
