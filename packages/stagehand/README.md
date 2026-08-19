# @openagentfence/stagehand

The Stagehand v4 adapter boundary for OpenAgentFence. Stagehand is an optional
peer dependency; `@openagentfence/core` never imports it (ADR-0002).

### Verified v4 behavior

- `observe()` responses are strictly bounded and normalized into conservative
  `CanonicalAction` candidates.
- `act()` executes only the exact structured candidate after one deterministic
  state-binding/revalidation cycle. Core atomically consumes the session-issued
  authorization immediately before the captured structured candidate reaches
  Stagehand; no parallel Stagehand authority remains. A wrapper without a
  `StagehandStateResolver` is disabled before `act()` is called; it never falls
  back to natural-language inference.
- A changed target retries once with a new observation and authorization;
  another mutation, an expired intent, malformed candidates, zero/multiple
  authorizations, or an unresolvable state fail closed.
- `extract()` accepts only bounded text and returns `UntrustedContent` with web
  provenance and `instructionEligible: false` after model-output scanning.
- Screenshot-first context contains only the captured screenshot and visible
  probe text. It does not claim screenshot/DOM semantic comparison.

### Surface coverage, Stagehand 4.0.1 development conformance

`observe` is read-only; `act`, `extract`, and screenshot-first are hooked when
their required adapters/hooks are supplied. Page controls, agent/batch, WebMCP
listing, and WebMCP invocation are explicitly disabled with a typed
`StagehandSecurityError` and zero framework calls. No Stagehand network surface
is claimed as enforced or observed because its minimal v4 abstraction exposes
no independently validated network-effect hook.

Consequently Stagehand has no POST_ACTION observation window for its remaining
guarded `act()` surface. It is explicitly `unavailable`, never a clean
post-action result; applications needing deterministic redirect, popup, or
download comparison must use an adapter with those event hooks.

Form submission, upload, and download are also explicitly disabled. Stagehand
4.0.1's observed action schema has no form action/method/field metadata, and
its public API has no download event, metadata, stream, or request-interception
hook. Although the underlying locator API has `setInputFiles`, the current
agent-facing action protocol cannot bind application/user provenance and an
exact file payload without exposing a new application-owned locator boundary.
Those paths remain fail-closed rather than inferred from natural-language act.
When the deterministic state resolver identifies a form action on an otherwise
generic click, the wrapper also blocks it before `Stagehand.act()` is called.

The public peer range is `^4.0.0`; compile-time conformance is pinned to 4.0.1.
Raw framework access remains an application escape hatch and must be recorded
by the owning `SecuritySession`.

**Status: not yet published.**
