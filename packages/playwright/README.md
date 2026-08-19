# @openagentfence/playwright

The Playwright adapter and secure wrapper of OpenAgentFence. Core never imports
Playwright; all Playwright-specific behavior stays in this package (ADR-0002).

**Implemented (M2, `OAF-BROWSER-001/002`):**

- `playwrightAdapter(page, options)` produces bounded per-frame observations,
  opaque page/context/frame identities and revisions, a core probe, ARIA
  snapshot, and opt-in bounded PNG screenshots. A frame whose probe cannot be
  read is retained with `embedded: true` rather than silently omitted.
- Event subscriptions receive a firewall-owned session identity and detach at
  session end. Navigation, popup, and download events retain opaque page/frame
  identity; request events normalize validated `NetworkMutation` records.
- `wrapPage(session, page)` exposes guarded `goto`, click, fill, type, press,
  select-option, submit controls, bounded in-memory `setInputFiles`, and
  `download` operations, plus `executeHelper` only when the application passes
  the same immutable `PlaywrightHelperRegistry` to wrapper and adapter. A
  helper is a TB1 application registration with stable name/SHA-256 hash and
  bounded JSON arguments; its function source and arguments never enter the
  action trace. Generic `evaluate`, script injection, dynamic fetch, storage,
  filesystem, and extension paths remain absent. Submit controls bind the
  resolved form action/method;
  uploads require user/application provenance, sensitivity, task necessity, and
  never accept filesystem paths; downloads return metadata (origin, MIME,
  filename, SHA-256, disposition, bytes) rather than content. Each creates a
  core-minted `AuthorizedAction`, re-resolves its target/attributes/visibility
  immediately before exact execution, and fails closed on mutation or expiry.
  Other execution paths are absent from the secure surface; raw page access
  remains the recorded escape hatch.

  After exact execution, the session holds a bounded 25 ms POST_ACTION event
  window and compares top-level navigation, popup, and download events with
  the immutable authorized action. Unexpected effects are detected after they
  occur, traced with stable reason codes, and raise monotonic session risk;
  this is not rollback or preflight redirect enforcement. An adapter without
  all required event hooks is recorded as unavailable and restricts subsequent
  authority rather than reporting a clean result.

  Download count is reserved during authorization and download bytes are
  reserved before the metadata is released. Missing MIME/disposition/origin or
  filename metadata, a failed/oversize budget reservation, or a metadata timeout
  fails closed; the wrapper deletes Playwright's temporary download and never
  returns its body.

### Playwright 1.62.1 capability snapshot

With routing disabled, only `navigation`, `fetch`, and WebSocket handshakes are
`observed_only`; no network surface is `enforced`. Redirect classification,
form/beacon/upload initiators, headers/body enforcement, service workers,
downloads/popups as network mutations, and WebMCP are `unavailable`. Popup and
download **events** are available separately, but are not egress enforcement.

Set `routeRequests: true` to enable the tested pre-request destination boundary
for initial HTTP(S) navigations and fetch/XHR. It aborts unsupported schemes,
private/local destinations, configured internal CIDR ranges, and navigation
outside the session envelope before the target receives a request. The local
integration suite asserts zero captured target requests for a blocked SSRF
fetch and cross-origin initial navigation.

Playwright invokes routing only for the first URL of a redirect chain. Later
redirect hops are therefore **`observed_only`**, not enforced; their origin and
hop metadata are recorded for the core redirect evaluator, but a follow-up hop
may already have reached its target. Form/beacon/upload initiator attribution,
headers/body enforcement, WebSocket frames, service workers, downloads,
popups, and WebMCP remain explicit observed-only or unavailable gaps. A proxy
or a framework hook that intercepts every redirect hop is required before
claiming redirect preflight blocking.

Popup events are post-creation only. The shared session consumes the tab budget
and evaluates an observable popup URL against the navigation envelope; the
adapter closes the popup immediately on an exhausted budget or disallowed URL.
This does not claim pre-navigation or zero-byte popup containment, does not
expose a secure child-page wrapper, and leaves taint propagation to PS-013.

Secret-handle-bearing Playwright operations remain disabled until executor-side
substitution lands in OAF-DATA-004. The guarded upload path accepts only
in-memory application/user payloads, never secret handles or paths. Download
metadata is obtained before it is returned to application/agent code; Playwright
cannot abort a download response after headers, so this is a pre-exposure
boundary, not a claim of network-level download interception. Script evaluation,
context/page creation, and close paths are not exposed by the secure wrapper.

**Status: not yet published.** No API is stable; see the
[implementation plan](../../docs/IMPLEMENTATION_PLAN.md).
