import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
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

/**
 * @param {string} command
 * @param {string[]} args
 * @param {string} cwd
 * @param {{ readonly shell?: boolean }} [options]
 */
function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    shell: options.shell ?? false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw new Error(`${command} ${args.join(" ")} failed: ${output}`);
  }
  return String(result.stdout);
}

/** @param {string[]} args @param {string} cwd */
function runPnpm(args, cwd) {
  const command = process.platform === "win32" ? "corepack.cmd" : "corepack";
  // Windows command shims are .cmd files and Node can only execute them
  // through the command shell. The arguments here are fixed by this script,
  // never application/release input.
  run(command, ["pnpm", ...args], cwd, { shell: process.platform === "win32" });
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
 * Changesets preserves workspace-star ranges. The local candidate stage reuses
 * source node_modules junctions that still describe unreleased versions.
 * Materialize published internal edges in staged manifests before packing so
 * the candidate is an npm-installable closed package set.
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
    const sourceNodeModules = resolve(root, "node_modules");
    if (!existsSync(sourceNodeModules)) {
      throw new Error("Release candidate requires installed workspace dependencies");
    }
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
    // Install while the manifests still retain workspace: ranges. pnpm then
    // resolves every internal edge to the staged workspace without consulting
    // a registry for the not-yet-published release candidate version.
    runPnpm(["install", "--ignore-scripts", "--frozen-lockfile"], stagedRoot);
    // Publishable tarballs must not retain workspace ranges. Do this only
    // after the staged workspace links exist, so the following build is still
    // a cold-stage build rather than an import from the source checkout.
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
