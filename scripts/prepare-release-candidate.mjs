import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { main as createReleaseArtifacts } from "./release-artifacts.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageNames = [
  "cli",
  "core",
  "playwright",
  "policy",
  "providers",
  "scanners",
  "stagehand",
  "testing",
  "vault",
];
const packageScope = "@openagentfence/";
const packageSpecifiers = new Set(packageNames.map((packageName) => packageScope + packageName));
const excludedTopLevel = new Set([".git", ".opencode", "artifacts", "node_modules", "coverage"]);

/** @param {string} value */
function sha256File(value) {
  return createHash("sha256").update(readFileSync(value)).digest("hex");
}

/** @param {string[]} args */
function parseArgs(args) {
  let version = "0.1.0-rc.1";
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--version") {
      version = args[index + 1] ?? "";
      index += 1;
      continue;
    }
    throw new Error("Usage: node scripts/prepare-release-candidate.mjs [--version 0.1.0-rc.1]");
  }
  if (!/^\d+\.\d+\.\d+-rc\.\d+$/u.test(version)) {
    throw new Error("Release candidate version must be an exact rc SemVer value");
  }
  return version;
}

/** @param {string} command @param {string[]} args @param {string} cwd */
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw new Error(`${command} ${args.join(" ")} failed: ${output}`);
  }
  return String(result.stdout);
}

/** @param {string} stagedRoot */
function writeSnapshotConfig(stagedRoot) {
  const path = resolve(stagedRoot, ".changeset", "config.json");
  const config = JSON.parse(readFileSync(path, "utf8"));
  config.snapshot = { useCalculatedVersion: true, prereleaseTemplate: "{tag}.1" };
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

/** @param {string} stagedRoot @param {string} version */
function assertCandidateVersion(stagedRoot, version) {
  const changelogs = [];
  for (const packageName of packageNames) {
    const packageDirectory = resolve(stagedRoot, "packages", packageName);
    const manifest = JSON.parse(readFileSync(resolve(packageDirectory, "package.json"), "utf8"));
    if (manifest.version !== version) {
      throw new Error(`${packageName} did not receive the requested release candidate version`);
    }
    const changelog = resolve(packageDirectory, "CHANGELOG.md");
    if (!existsSync(changelog) || readFileSync(changelog, "utf8").trim() === "") {
      throw new Error(`${packageName} release candidate is missing a generated changelog`);
    }
    changelogs.push({
      package: manifest.name,
      path: `packages/${packageName}/CHANGELOG.md`,
      hash: sha256File(changelog),
    });
  }
  return changelogs;
}

/**
 * Changesets preserves workspace-star ranges. Materialize published internal
 * edges in staged manifests before packing so the candidate is an
 * npm-installable closed package set.
 *
 * @param {string} stagedRoot
 * @param {string} version
 */
function materializeCandidateInternalDependencies(stagedRoot, version) {
  for (const packageName of packageNames) {
    const manifestPath = resolve(stagedRoot, "packages", packageName, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    let changed = false;
    for (const group of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      const dependencies = manifest[group];
      if (dependencies === undefined) continue;
      if (
        dependencies === null ||
        typeof dependencies !== "object" ||
        Array.isArray(dependencies)
      ) {
        throw new Error(packageName + " has an invalid " + group + " manifest entry");
      }
      for (const dependencyName of Object.keys(dependencies)) {
        if (!dependencyName.startsWith(packageScope)) continue;
        if (!packageSpecifiers.has(dependencyName)) {
          throw new Error(packageName + " references an unpublished internal dependency");
        }
        if (dependencies[dependencyName] !== version) {
          dependencies[dependencyName] = version;
          changed = true;
        }
      }
    }
    if (changed) writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  }
}

/** @param {string} stagedRoot */
function candidateChangesets(stagedRoot) {
  return readdirSync(resolve(stagedRoot, ".changeset"), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => entry.name)
    .sort();
}

/** @param {string} stagedRoot */
function linkStagedDependencies(stagedRoot) {
  const sourceNodeModules = resolve(root, "node_modules");
  if (!existsSync(sourceNodeModules)) {
    throw new Error("Release candidate requires installed workspace dependencies");
  }
  const linkType = process.platform === "win32" ? "junction" : "dir";
  // Reuse immutable root tooling and every package's external dependencies
  // from the frozen source installation, but give staged packages their own
  // higher-precedence workspace links. This prevents a staged build from
  // importing a source-checkout package or asking the registry for a
  // not-yet-published RC version.
  symlinkSync(sourceNodeModules, resolve(stagedRoot, "node_modules"), linkType);
  const stagedScope = resolve(stagedRoot, "packages", "node_modules", "@openagentfence");
  mkdirSync(stagedScope, { recursive: true });
  for (const packageName of packageNames) {
    symlinkSync(
      resolve(stagedRoot, "packages", packageName),
      resolve(stagedScope, packageName),
      linkType,
    );

    const sourcePackageNodeModules = resolve(root, "packages", packageName, "node_modules");
    if (!existsSync(sourcePackageNodeModules)) continue;
    const stagedPackageNodeModules = resolve(stagedRoot, "packages", packageName, "node_modules");
    mkdirSync(stagedPackageNodeModules, { recursive: true });
    for (const entry of readdirSync(sourcePackageNodeModules, { withFileTypes: true })) {
      // Internal dependencies must resolve to the staged candidate rather
      // than their unversioned source-checkout links.
      if (entry.name === "@openagentfence") continue;
      symlinkSync(
        resolve(sourcePackageNodeModules, entry.name),
        resolve(stagedPackageNodeModules, entry.name),
        linkType,
      );
    }
    const stagedPackageScope = resolve(stagedPackageNodeModules, "@openagentfence");
    mkdirSync(stagedPackageScope, { recursive: true });
    for (const dependencyPackageName of packageNames) {
      symlinkSync(
        resolve(stagedRoot, "packages", dependencyPackageName),
        resolve(stagedPackageScope, dependencyPackageName),
        linkType,
      );
    }
  }
}

function stageCurrentWorkspace() {
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), "openagentfence-rc-"));
  const stagedRoot = resolve(temporaryRoot, "workspace");
  try {
    cpSync(root, stagedRoot, {
      recursive: true,
      filter(source) {
        const segments = relative(root, source).split(sep);
        return !segments.some((segment) => excludedTopLevel.has(segment));
      },
    });
    linkStagedDependencies(stagedRoot);
    return { temporaryRoot, stagedRoot };
  } catch (error) {
    rmSync(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
}

export function main(args = process.argv.slice(2)) {
  const version = parseArgs(args);
  const { temporaryRoot, stagedRoot } = stageCurrentWorkspace();
  try {
    const inputChangesets = candidateChangesets(stagedRoot);
    if (inputChangesets.length === 0)
      throw new Error("Release candidate requires pending Changesets");
    writeSnapshotConfig(stagedRoot);
    const changesetCli = resolve(root, "node_modules", "@changesets", "cli", "bin.js");
    if (!existsSync(changesetCli))
      throw new Error("Release candidate requires the installed Changesets CLI");
    run(process.execPath, [changesetCli, "version", "--snapshot", "rc"], stagedRoot);
    // Publishable tarballs must not retain workspace ranges. The staged
    // workspace links already bind build-time internal imports to this
    // candidate, not the unversioned source checkout.
    materializeCandidateInternalDependencies(stagedRoot, version);
    const changelogs = assertCandidateVersion(stagedRoot, version);
    run(
      process.execPath,
      [resolve(stagedRoot, "scripts", "build-release-packages.mjs")],
      stagedRoot,
    );
    createReleaseArtifacts(
      ["--out", "artifacts/release", "--require-publishable", "--version", version],
      stagedRoot,
    );
    const output = resolve(root, "artifacts", "release");
    const audit = resolve(output, "package-audit.json");
    const sbom = resolve(output, "openagentfence.cdx.json");
    const manifest = {
      format: "openagentfence-release-candidate-v1",
      version,
      source: "recoverable local Changesets snapshot staging",
      changesets: inputChangesets,
      changelogs,
      packageAudit: { path: "package-audit.json", sha256: sha256File(audit) },
      sbom: { path: "openagentfence.cdx.json", sha256: sha256File(sbom) },
    };
    writeFileSync(
      resolve(output, "release-candidate.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    );
    process.stdout.write(
      `prepared local ${version} candidate with ${changelogs.length} package changelogs\n`,
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
