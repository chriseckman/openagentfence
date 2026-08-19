## Summary

<!-- What does this change do and why? Link the task id (e.g. OAF-CORE-007). -->

## Security invariants touched

<!-- Which INV-nn / trust boundaries (TBn) does this change affect, and how is it tested? -->

## Checklist

- [ ] Tests added or updated (unit; integration where behavior touches a browser or adapter).
- [ ] A security-corpus fixture was added when the change is security-related.
- [ ] No raw secret, credential, or real API key appears in code, fixtures, or traces (INV-05).
- [ ] Commits follow Conventional Commits and are DCO signed-off (`git commit -s`).
- [ ] `pnpm lint`, `pnpm typecheck`, and `pnpm test` pass locally.

<!-- Scanner-internals changes only -->
- [ ] I attest I have not read the Agent Browser Shield source, and this implementation is independent (ADR-0006).
