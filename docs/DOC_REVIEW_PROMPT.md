# Documentation review and validation

Use this review for any documentation change and before a milestone or release
claims documentation closure. It is the repository's executable documentation
contract referenced by `AGENTS.md`.

## Required review

1. Reconcile claims against the source-of-truth order in `AGENTS.md` and the
   current implementation. Do not describe `observed_only` or `unavailable`
   adapter surfaces as enforced.
2. Check public examples against current package exports and required security
   arguments. Examples must not invent facade methods or omit fail-closed
   resolver/configuration requirements.
3. Distinguish implemented P0 behavior, active milestone work, P1/deferred
   work, and external release state. Never claim publication, remote checks,
   provenance, signing, or benchmark results without evidence.
4. Verify external-call disclosures, secret/credential handling, capability
   defaults, framework/provider versions, and unsupported surfaces.
5. Preserve clean-room provenance and the OpenAgentFence identity from
   ADR-0006 and ADR-0007.

## Required commands

Run from the repository root:

```text
pnpm docs:check
pnpm format:check
git diff --check
rg -n -i --pcre2 "(?<!open)agent[f]ence" . --glob "!node_modules/**" --glob "!dist/**" --glob "!coverage/**" --glob "!.git/**" --glob "!artifacts/**" --glob "!packages/*/temp/**" --glob "!packages/*/etc/*.api.md"
```

`pnpm docs:check` validates every relative Markdown file link and local
Markdown heading/explicit-anchor fragment across tracked project Markdown,
excluding generated and dependency directories.
The legacy-name scan may report only the historical rename note in `AGENTS.md`
and the naming history in ADR-0007. Review each hit; a new product/package/API
use of the legacy name fails the review.

For public API or configuration examples, also run the affected package
typecheck/tests and `pnpm api-report:check`. For workflow or release claims,
run `pnpm check:workflow` and the prompt-specific release dry-run checks.

## Completion record

Record the exact commands, counts, versions, and any intentionally unsupported
surface in the owning prompt/PR evidence. A missing procedure, broken link or
anchor, stale capability claim, invented API, or unexplained legacy-name hit is
a documentation failure, not a warning.
