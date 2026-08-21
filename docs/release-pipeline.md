# Release pipeline

OpenAgentFence packages are prepared locally and published only by the
repository's protected `Authorized package release` workflow. The workflow is
deliberately a release mechanism, not a promise that a release has happened.

## Local, non-mutating verification

Run the following after a Changesets version-preparation commit:

```text
pnpm install --frozen-lockfile
pnpm check:workflow
pnpm legal:check
pnpm release:dry-run
```

`release:dry-run` rebuilds the workspace, creates pnpm-packed publication tarballs under
`artifacts/release/`, rejects source maps, tests, environment files, and
unexpected dependency material, and writes a package-content audit plus a
CycloneDX 1.7 SBOM. It never creates a tag, contacts npm, or mutates a GitHub
release. The audit requires the root Apache-2.0 `LICENSE` and `NOTICE` in each
published tarball and verifies each package's repository metadata and exported
schemas.

The SBOM is a deterministic inventory of the direct published workspace graph
and installed direct runtime/peer versions. It is an artifact inventory, not a
claim of remote npm provenance or a substitute for a consumer vulnerability
assessment.

## Required release preparation

Before any external release action, a maintainer must:

1. Review and merge the intended Changesets version-preparation commit.
2. Run the full repository validation pipeline and the local release dry run.
3. Confirm every public package has the exact version requested for the tag and
   that each **packed** manifest has no `workspace:`, `file:`, or `link:`
   runtime dependency and every `@openagentfence/*` edge is the exact requested
   release version. The audit reads `package/package.json` from every tarball;
   source manifests intentionally retain workspace protocols.
4. Configure the `release` GitHub environment with required reviewers,
   `OAF_RELEASE_SIGNING_KEY`, and the matching
   `OAF_RELEASE_SIGNING_FINGERPRINT` variable. The signing key is base64-encoded
   only for transport into the protected runner, imported into a temporary
   `GNUPGHOME`, and never written to the repository or an artifact.
5. Configure npm trusted publishing for each public package with the exact
   `chriseckman/openagentfence` repository and `release.yml` workflow. npm
   requires Node 22.14+ and npm 11.5+ for trusted publishing. Configure the
   allowed action and environment where npm requires them, and disallow
   long-lived publish tokens after verification.
6. Obtain fresh maintainer approval immediately before dispatching the
   irreversible publish job.

The final item is mandatory even though the protected GitHub environment also
requires approval. It records the D-05 authorization boundary for tag creation,
npm publication, artifact attestation, and GitHub release creation.

## Remote workflow behavior

The dispatch workflow always starts with a verification job using only
`contents: read`. Its publish job is disabled unless the dispatcher sets
`publish: true` from `main`, and is the only workflow job granted
`contents: write`, `id-token: write`, and `attestations: write`.

After protected-environment approval, the publish job rebuilds and audits the
artifacts, performs an isolated install/import/CLI/quick-start smoke check,
signs and verifies `v<version>` with the isolated key, publishes each exact
audited tarball using `npm publish <tarball> --provenance --access public`,
attests the tarballs with the CycloneDX SBOM, and creates a GitHub release
containing the tarballs, SBOM, and package audit. It does not accept an npm
publish token.

## Local release candidates

`pnpm release:candidate` creates a recoverable local `0.1.0-rc.1` Changesets
snapshot in a temporary worktree. It leaves the checkout's final-release
Changesets and package versions unchanged, generates the candidate changelogs
only in that temporary staging area, materializes every staged internal
dependency to the exact RC version, then writes audited RC tarballs, the SBOM,
and `artifacts/release/release-candidate.json`. It also installs the packed
artifacts without dependency overrides in an offline temporary consumer, imports every package root and
published schema, and runs packed `init`, `policy validate`, `doctor`, and a
public-import secure quick start. No tag, npm publish, or GitHub mutation is
performed.

The ordinary CI workflow runs this candidate creation, artifact audit, and
offline consumer smoke on Node 24. Its uploaded output remains local CI
evidence only; it does not confer trusted publishing, tag, provenance, or
release status.

After a successful remote release, verify the signed tag, GitHub release assets
and attestation, each npm provenance panel, and a clean consumer installation.
Record immutable tag, release, npm package/version, SBOM hash, and attestation
identifiers in the release checklist.

## Current external status

Local workflow and artifact checks are implemented. Remote branch protection,
deployed workflow/check context, protected release environment, npm trusted
publisher mappings, signing-key custody, and GitHub/npm verification are
external prerequisites. Their current known status is tracked in
[branch protection](branch-protection.md); none is implied by a local dry run.

The current local RC evidence and the remaining PS-025 external rows are kept
in the [v0.1 release checklist](release-checklist-v0.1.md).

## References

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements/)
- [GitHub artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
