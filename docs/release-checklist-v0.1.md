# v0.1 release checklist

This is the release-PR checklist for OpenAgentFence v0.1. It distinguishes
current, reproducible local evidence from the irreversible external evidence
that only PS-025 may record after fresh maintainer approval.

## Local RC evidence

- Candidate intent: `0.1.0-rc.1`, assembled by `pnpm release:candidate` in a
  recoverable Changesets snapshot staging directory. The checkout intentionally
  retains its final-release Changesets and `0.0.0` source manifests until the
  authorized release preparation.
- Candidate artifacts: nine pnpm-packed tarballs, `package-audit.json`,
  CycloneDX 1.7 SBOM, and `release-candidate.json` under the ignored local
  `artifacts/release/` directory. The candidate manifest records the exact
  artifact and generated-changelog hashes.
- Consumer proof: the release smoke installs only the audited tarballs and a
  locally packed `yaml@2.9.0` dependency with `npm --offline`; it imports every
  package root and published schema, runs packed `init`, `policy validate`, and
  `doctor`, then runs the scanner-enabled public-import quick start. It neither
  contacts npm nor invokes a provider or browser.

The current local candidate was regenerated on 2026-08-21 with the following
SHA-256 evidence. These are local RC artifacts, not remote release identifiers:

| Artifact | SHA-256 |
|---|---|
| `package-audit.json` | `b7ffeb0053f364e9776aaf711790cadb7b2f7789e697bbdfc8a5d2eb7e5327bb` |
| `openagentfence.cdx.json` | `ef0c3b1e9fe0739a1dd1bd4a13bd69e6bfeac4b7d32ba65dad8b79aa3f096e2a` |
| `release-candidate.json` | `e76b4ba403038a1ceef27f3c46210f4cf5fe0227ee328a1d1951fd6039edb62d` |

Regenerate and check the current candidate rather than relying on a prior
artifact:

```text
pnpm release:candidate
pnpm test:release-artifacts
```

## v0.1 required product ledger

All rows below have current executable evidence; exact command results are
recorded in the series `STATE.md` at each prompt boundary.

| PRD §27 row | Requirement | Current local evidence |
|---:|---|---|
| 1 | TypeScript core | `@openagentfence/core`; `pnpm test` and API report |
| 2 | Stagehand adapter | Stagehand 4.0.1 recorded scenarios; `pnpm --filter @openagentfence/stagehand test` |
| 3 | Playwright adapter | Chromium integration; `pnpm test:integration` |
| 4 | Trusted task contract | Core contract and invariant suites |
| 5 | Canonical actions | Core authorization and property suites |
| 6 | Visibility classifier | Perception corpus |
| 7 | ARIA anomaly detection | Perception corpus |
| 8 | Hidden/comment/metadata/attribute scanners | Perception corpus |
| 9 | Encoded normalizer | Decoder fuzz and perception corpus |
| 10 | Deterministic injection heuristics | Perception corpus and invariant suite |
| 11 | BYOK text injection classifier | Providers/scanners tests; evidence-only router |
| 12 | Secret detection | Scanner and data-control integration tests |
| 13 | Secret handle API | Vault/resolver/executor regression suite |
| 14 | Origin/navigation policy | Navigation corpus and destination tests |
| 15 | Private-network blocking | SSRF corpus and routed zero-byte tests |
| 16 | Pre-action authorization | Core/runtime and adapter integration tests |
| 17 | Upload/download hooks | Action/security corpus with documented capability gaps |
| 18 | Form policy | Exact-state integration and observed-only network ledger |
| 19 | Risk/restricted mode | Risk, taint, popup, and invariant suites |
| 20 | Guarded memory read/write | Memory corpus and fresh-session integration |
| 21 | Structured security traces | Trace validation and CLI explain tests |
| 22 | YAML policy | Policy loader/CLI validation tests |
| 23 | Malicious-page corpus | `pnpm test:corpus` (227 cases) |
| 24 | CI-friendly corpus command | Packed CLI corpus command and CI job |
| 25 | Promptfoo example | `pnpm promptfoo:check` (offline loopback) |
| 26 | Apache-2.0 | Root and packed legal-file audit |
| 27 | Security policy/threat model | Invariant coverage registry and docs checks |
| 28 | Session budgets | Core budget/property/provider tests |
| 29 | Approval handlers | High-impact corpus and approval tests |
| 30 | Engineering baseline | Lint/type/API/docs/dependency/workflow gates |
| 31 | Exact execution/revalidation | Mutation corpus and adapter regressions |
| 32 | Network Mutation Guard | Network corpus; explicit enforced/observed/unavailable matrix |
| 33 | Trusted Intent isolation | Core intent isolation/property evidence |
| 34 | Three-tier detectors | Router/BYOK/invariant evidence |
| 35 | Bounded untrusted/provider work | Property/fuzz/provider bounds evidence |
| 36 | Adaptive corpus/TOCTOU/WebMCP fixtures | Corpus schema, mutation corpus, and Stagehand recordings |

The all-invariant, attack-class, and Security Guarantee Matrix links are
maintained in [the Threat Model](THREAT_MODEL.md). P1 scope remains explicitly
deferred in [the implementation plan](IMPLEMENTATION_PLAN.md#122-explicitly-deferred-prd-27-33).

## Required local gate

Before requesting release authorization, rerun the documented sequence:

```text
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm test:corpus
pnpm test:property
pnpm test:invariants
pnpm benchmark:pr
pnpm promptfoo:check
pnpm examples:check
pnpm audit:dependencies
pnpm api-report:check
pnpm docs:check
pnpm format:check
pnpm check:deps
pnpm check:workflow
pnpm release:candidate
git diff --check
```

`pnpm release:candidate` includes the isolated packed-artifact smoke and
cross-checks audit/SBOM hashes. It is local-only evidence, not a provenance or
publication claim.

## PS-025 external release rows — open

The following rows remain deliberately open and must be verified at release
time. Do **not** sign them off based on local files or this checklist.

- D-03: GitHub `main` branch/ruleset protection and deployed required-check
  evidence. Current remote evidence is no branch protection, no rulesets, and
  no deployed TypeScript workflow configuration; see
  [branch protection](branch-protection.md).
- D-04: protected `release` environment, independent reviewer policy, signing
  key/fingerprint custody, and npm trusted-publisher mapping for every public
  package.
- D-05: fresh explicit maintainer authorization immediately before the
  irreversible tag/npm/GitHub release dispatch.
- Remote signed tag, GitHub release assets, artifact-attestation identifier,
  npm package/version provenance panels, and post-publish clean consumer
  installation.
- Final immutable release identifiers, final artifact/SBOM hashes, and
  release timestamp must be recorded after—not before—the remote workflow
  succeeds.

## Capability and deferred-work record

The release does not claim unsupported controls. Playwright has pre-effect
enforcement only for routed initial navigation/fetch; redirects, forms,
headers, WebSockets, beacons, uploads, and downloads are observed-only where
measurable, while service workers, popups, and WebMCP are unavailable. Stagehand
network/WebMCP and secret sinks remain disabled or unavailable. OpenCode guard
construction is typed unavailable. No default provider is configured, no model
is recommended, no live provider is measured, and P1 replay, bypass detection,
profiles, visual semantic matching, data-flow graph, proxy, and persistent
receipt work remain deferred.
