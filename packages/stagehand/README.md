# @openagentfence/stagehand

The Stagehand v4 adapter boundary for OpenAgentFence. Stagehand is an optional
peer dependency; `@openagentfence/core` never imports it (ADR-0002).

### Verified v4 behavior

The supported and tested SDK version is exactly Stagehand 4.0.1 on Node.js
22.18.0 or newer. The peer range is intentionally exact until another minor
passes the same conformance and recorded-scenario suite.

- `observe()` responses are strictly bounded and normalized into conservative
  `CanonicalAction` candidates.
- `act()` requires the application to construct Stagehand with `selfHeal:
  false` and attest that setting to the wrapper. It executes only the exact,
  deeply frozen structured candidate after one deterministic
  state-binding/revalidation cycle. Core atomically consumes the session-issued
  authorization immediately before the captured structured candidate reaches
  Stagehand; no parallel Stagehand authority remains. A wrapper without a
  `StagehandStateResolver` is disabled before `act()` is called; it never falls
  back to natural-language inference.
- A changed target retries once with a new observation and authorization;
  another mutation, an expired intent, malformed candidates, zero/multiple
  authorizations, or an unresolvable state fail closed.
- `extract()` accepts only bounded text and returns `UntrustedContent` with
  tool provenance and `instructionEligible: false` after model-output
  scanning. It cannot acquire application authority from the extraction path.
- Screenshot-first context contains only the captured screenshot and visible
  probe text. Visible text is a provenance-bearing firewall value rather than
  a raw string, and releasing it activates the shared session taint floor. It
  does not claim screenshot/DOM semantic comparison.

### Surface coverage, Stagehand 4.0.1 development conformance

`observe` is read-only and bounded to 64 candidates; `act`, `extract`, and screenshot-first are hooked when
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

Secret-bearing actions are a separate disabled surface. In pinned Stagehand
4.0.1, generic `act(Action)` can expose action arguments through result/log/error
paths and configured self-healing can invoke a model after a failed structured
action. OpenAgentFence therefore permits `observe()` to see only the opaque
handle and throws `unsupported_secret_sink` before `act()` receives the action.
No Stagehand fill/type/header/file/message sink currently claims raw-secret
substitution. A future claim requires an independently state-bound public
locator bridge with zero model calls and leak conformance.

The public peer range and compile-time conformance are pinned to `4.0.1`.
Raw framework access remains an application escape hatch and must be recorded
by the owning `SecuritySession`.

Stagehand's exact-action consumption uses an unsupported adapter-only core
integration bridge, not a root `SecuritySession` callback. Applications must
use `wrapStagehand()` and must not import core internal entry points. The
[v0.1 API stability ledger](../../docs/api-stability.md) records this boundary.

The closed, bounded offline scenario fixture and runner are documented in
[`docs/stagehand.md`](../../docs/stagehand.md). They cover 24 recorded corpus-linked
scenarios and use no live model, credential, or external network call.

**Status: experimental through v0.3.**
