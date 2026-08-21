# v0.1 API stability ledger

Every export from the root entry point of each published package is
**experimental** for the v0.1 line. No root symbol is semver-stable before
v0.3. The generated API reports below are the exhaustive, versioned symbol
inventory; a report update and this ledger must be reviewed together.

| Package | Exhaustive inventory | v0.1 status | Supported use |
| --- | --- | --- | --- |
| `@openagentfence/cli` | `packages/cli/etc/cli.api.md` | binary-oriented, experimental package metadata only | Invoke `openagentfence`; command modules are not a programmatic API. |
| `@openagentfence/core` | `packages/core/etc/core.api.md` | experimental | Framework-neutral contracts and facade composition only. Root excludes raw vault construction and Stagehand exact-execution bridges. |
| `@openagentfence/policy` | `packages/policy/etc/policy.api.md` | experimental | Application-owned bounded policy loading, validation, and engine construction. |
| `@openagentfence/vault` | `packages/vault/etc/vault.api.md` | experimental | Reference vault configuration only; raw lookup requires an unforgeable core executor capability. |
| `@openagentfence/scanners` | `packages/scanners/etc/scanners.api.md` | experimental | Built-in scanner catalog and analysis helpers. Custom in-process scanners are trusted; plugins use `definePluginScanner`. |
| `@openagentfence/providers` | `packages/providers/etc/providers.api.md` | experimental | Application-owned provider factories. Credentials remain closure-private and must never be traced or logged. |
| `@openagentfence/playwright` | `packages/playwright/etc/playwright.api.md` | experimental | Guarded wrapper/adapter composition. `rawPage` is an explicitly recorded escape hatch; capability descriptors do not create a browser. |
| `@openagentfence/stagehand` | `packages/stagehand/etc/stagehand.api.md` | experimental | Verified Stagehand 4.0.1 secure wrapper and typed disabled-surface ledger only. |
| `@openagentfence/testing` | `packages/testing/etc/testing.api.md` | experimental, non-production | Offline fixture, corpus, assertion, and benchmark support; never import it in production runtime paths. |

## Security-sensitive boundaries

- `VaultAdapter`, `SessionVault`, `ExecutorSecretLookup`, and `SecretResolver`
  are extension contracts, not application secret-read APIs. A reference vault
  opens a session and returns lookup access only after receiving a capability
  minted inside `core`; adapters receive values only through an action-scoped
  resolver after exact sink revalidation (ADR-0005, INV-04/05).
- `SecuritySession.executeAuthorized()` is the public browser-adapter path.
  The Stagehand exact-execution bridge is an unsupported `@openagentfence/core/internal`
  adapter integration detail and is absent from the root API; it must not be
  used by applications.
- `SecuritySession.unsafe.rawPage(reason)` is the sole supported raw framework
  access route and records a redacted `escape_hatch` trace event first. Adapter
  `rawPage` methods require a session-minted capability (INV-18).
- Guard-provider output, decoder/fold output, and scanner heuristics are
  analysis evidence only. They never authorize an action or form a released
  data carrier on their own; released sanitizer, finding, trace, memory, and
  egress values retain `DataProvenance` (INV-13/20).

## Review rules

Each API change must update its generated report, this ledger when its
package/safety classification changes, package documentation, a changeset,
and a consumer/security regression. Root `internal` entry points are excluded
from the public inventory and are reserved for repository-owned adapter
composition; importing them is unsupported and may break without notice.
