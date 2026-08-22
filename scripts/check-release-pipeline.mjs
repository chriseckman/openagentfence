import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const workflows = resolve(root, ".github", "workflows");
const release = readFileSync(resolve(workflows, "release.yml"), "utf8");
const actionPin = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6";

if (!release.includes("workflow_dispatch:") || release.includes("pull_request:")) {
  throw new Error("Release workflow must be explicitly dispatched and never run on pull requests");
}
if (
  !release.includes("environment: release") ||
  !release.includes("id-token: write") ||
  !release.includes("attestations: write")
) {
  throw new Error(
    "Release publish job must use the protected release environment and OIDC attestation permissions",
  );
}
if (
  !release.includes(actionPin) ||
  !release.includes("--provenance") ||
  !release.includes("git tag -s")
) {
  throw new Error("Release workflow must pin attestation, request npm provenance, and sign tags");
}
for (const requiredCheck of [
  "pnpm release:dry-run",
  "check:workflow",
  "pnpm promptfoo:check",
  "pnpm examples:check",
  "pnpm audit:dependencies",
  "release-candidate-smoke.mjs",
]) {
  if (!release.includes(requiredCheck)) {
    throw new Error("Release verification must run every local release validation surface");
  }
}
if (!release.includes('npm publish "$tarball" --provenance --access public')) {
  throw new Error(
    "Release publishing must use the exact audited tarballs, not workspace directories",
  );
}
for (const fileName of readdirSync(workflows)) {
  if (!fileName.endsWith(".yml")) continue;
  const contents = readFileSync(resolve(workflows, fileName), "utf8");
  if (fileName === "release.yml" || !/id-token:\s*write/.test(contents)) continue;
  if (
    fileName === "publish-pypi.yml" &&
    /environment:\s*\n\s*name:\s*pypi/.test(contents) &&
    /pypa\/gh-action-pypi-publish@/.test(contents) &&
    /permissions:\s*\n\s*id-token:\s*write/.test(contents)
  ) {
    continue;
  }
  {
    throw new Error(`${fileName} must not receive an OIDC token`);
  }
}
process.stdout.write("verified least-privilege npm and PyPI release workflow structure\n");
