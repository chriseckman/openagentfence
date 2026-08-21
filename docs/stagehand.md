# Stagehand v4 security boundary

`@openagentfence/stagehand` supports exactly Stagehand 4.0.1 for v0.1
conformance. The adapter package requires Node.js 22.18.0 or newer, matching
that installed SDK version. It does not claim compatibility with other v4
minors until those versions pass the same offline suite.

## Secure construction

Stagehand's official v4 behavior makes structured `act(Action)` deterministic
only when global self-healing cannot re-enter model inference. Construct the
Stagehand instance with `selfHeal: false`, then attest the same trusted setting
to the wrapper:

```ts
const secure = wrapStagehand(session, stagehand, {
  stateResolver,
  selfHeal: false,
});
```

The wrapper fails with `unsafe_self_heal_configuration` if that assertion is
missing. This is a trusted application configuration boundary; page content
cannot set it. The wrapper then observes exactly one structured action, binds
its target/page state to an `ActionIntent`, revalidates immediately before
execution, and passes only the deeply frozen action object to `act()`. It never
passes the original natural-language instruction to `act()`.

See the compile-checked [Stagehand local example](../examples/stagehand-local/)
and [screenshot-first example](../examples/screenshot-first/).

## Surface coverage

The exported `STAGEHAND_SURFACE_COVERAGE` ledger is exercised by the recorded
4.0.1 scenario suite.

| Surface | Status | Security disposition |
| --- | --- | --- |
| `observe` | `read_only` | Response shape, action count, selectors, descriptions, methods, and arguments are bounded and validated as untrusted data. |
| `act` | `hooked` | Requires `selfHeal: false`, one exact structured action, deterministic state resolution, authorization, and immediate revalidation. |
| `extract` | `hooked` | Text only; bounded and returned as non-instruction-eligible untrusted tool content. |
| screenshot-first | `hooked` | Screenshot plus firewall-scanned visible text; hidden DOM is withheld. No screenshot/DOM discrepancy claim. |
| secret sinks | `disabled` | Generic v4 action paths can expose values to cache/log/result/self-heal surfaces; handles never resolve through Stagehand. |
| form/upload/download | `disabled` | The observed action protocol lacks the complete state/file/effect metadata required for a bound sink. |
| page control, agent, batch | `disabled` | No wrapper path can bypass the exact-action boundary. |
| WebMCP list/invoke | `disabled` | Page-published manifest/schema/annotation/output and network-effect hooks are incomplete. |
| all network surfaces | `unavailable` | No independent Network Mutation Guard hook is claimed. |

Stagehand has no claimed POST_ACTION observation window. Applications needing
pre-request network enforcement, popup/download events, or deterministic
locator secret substitution use `@openagentfence/playwright`.

## Recorded offline verification

[`v4-recordings.json`](../packages/stagehand/test/scenarios/v4-recordings.json)
is a closed, bounded, versioned data fixture linked to committed security
corpus cases. The test runner validates it before use and covers exact action,
empty/ambiguous observation, target/destination/frame/visibility mutation,
poisoned and malformed extraction, screenshot-first containment, poisoned
WebMCP metadata/output, secret handles, file/form effects, disabled paths, and
the recorded raw-framework escape hatch. Unauthorized scenarios assert zero
framework execution. No live model, provider credential, or external network
call is used.

The exact SDK type surface is compile-checked by
[`v4-conformance.test.ts`](../packages/stagehand/test/v4-conformance.test.ts).
The shared hidden-DOM vertical slice also runs through the independent
Playwright adapter; this does not upgrade Stagehand's unavailable browser
event/network capabilities.

## Escape hatch

Applications can retain raw framework objects, so bypass resistance ultimately
depends on supplying only the secure wrapper to agent code. Any deliberate raw
page access must go through `session.unsafe.rawPage(reason)`, which records an
`escape_hatch` event before returning the adapter handle. Calling the retained
Stagehand instance directly is outside the secured surface and must not be
presented as guarded execution.

Official references: [Stagehand v4 act](https://docs.stagehand.dev/v4/basics/act),
[observe](https://docs.stagehand.dev/v4/basics/observe),
[extract](https://docs.stagehand.dev/v4/basics/extract), and
[WebMCP](https://docs.stagehand.dev/v4/basics/webmcp).
