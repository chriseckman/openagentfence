# ADR-0012: Policy parser approval

- **Status:** Accepted
- **Date:** 2026-08-17
- **Accepted:** 2026-08-17 by maintainer authorization
- **Related:** PRD §13.15-13.16; [ARCHITECTURE.md](../ARCHITECTURE.md) §3, §7,
  §17; [ADR-0008](0008-policy-loading-and-facade-boundary.md);
  [ADR-0009](0009-application-owned-provider-runtime-configuration.md);
  INV-01, INV-05, INV-16; TB1

## Context

OAF-POLICY-001 requires a bounded YAML/JSON policy document boundary. The
`@openagentfence/policy` package currently has no parser dependency or loader;
a handwritten YAML parser cannot safely satisfy the required alias, tag, depth,
and malformed-input controls. Adding a dependency to `policy` requires a
maintainer-accepted ADR under `AGENTS.md`.

ADR-0008 was amended on 2026-08-17 to stage document validation in PS-001 and
document evaluation in PS-002. This proposal is now limited to selecting the
new security-path parser dependency needed for PS-001.

## Decision

1. The approved direct parser dependency is **`yaml@2.9.0`**, pinned exactly
   in `@openagentfence/policy` and the lock file. Its published Node engine is
   `>=14.6` (therefore Node 20 compatible) and it includes declarations.
   `tsc --skipLibCheck false -p packages/policy/tsconfig.build.json` passed
   under the repository TypeScript 5.6.3 toolchain. `pnpm audit --prod` found
   no known vulnerabilities on 2026-08-17. The release was published on
   2026-05-11, providing current maintenance evidence. It provides documented
   strict, string-key/duplicate-key, alias-count, custom-tag, merge, and schema
   controls. No compiler setting or TypeScript version was changed for it.
2. The policy loader must cap bytes before parsing, reject aliases, merge keys,
   custom/explicit tags, duplicate/non-string keys, excessive depth/nodes, and
   unsafe object keys; it must construct fresh null-prototype-free data and
   produce bounded path-only errors. Parser configuration alone is not enough.

## Options considered

- **Handwritten YAML subset parser.** Rejected: it cannot provide a credible
  security boundary for aliases, tags, malformed syntax, and depth limits.
- **Add the latest parser release immediately.** Rejected: compatibility and
  security review must precede a new security-path dependency.

## Consequences

- Positive: parser bounds and dependency provenance are reviewable before
  untrusted YAML reaches a security-sensitive path.
- Follow-up: select and review the exact parser release, implement PS-001
  validation/fixtures, then complete PS-002's engine API.

## Security impact

This strengthens INV-01 and INV-16 by preventing unbounded or unsafe policy
deserialization. It preserves INV-05 by rejecting provider/runtime fields
before construction, hashing, tracing, or error reporting. Tests must cover
oversize input, aliases, custom tags, deep nesting, pollution keys,
environment-substitution syntax, and provider configuration rejection.

## References

- [YAML parser options](https://eemeli.org/yaml/) (`maxAliasCount`, strict,
  string-key, and unique-key controls)
- [YAML project releases](https://github.com/eemeli/yaml/releases)
