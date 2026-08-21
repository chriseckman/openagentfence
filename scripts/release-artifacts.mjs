import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const releaseRoot = resolve(root, "artifacts", "release");
const pnpmCliCandidates = [
  process.env.OAF_PNPM_CLI,
  process.env.LOCALAPPDATA &&
    resolve(
      process.env.LOCALAPPDATA,
      "node",
      "corepack",
      "v1",
      "pnpm",
      "9.15.4",
      "bin",
      "pnpm.cjs",
    ),
  process.env.COREPACK_HOME &&
    resolve(process.env.COREPACK_HOME, "v1", "pnpm", "9.15.4", "bin", "pnpm.cjs"),
].filter((candidate) => typeof candidate === "string" && existsSync(candidate));
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
const publishedPackageSpecifiers = new Set(
  packageNames.map((packageName) => packageScope + packageName),
);

/** @param {string} value */
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

/** @param {string} value */
function sha256File(value) {
  return sha256(readFileSync(value));
}

/** @param {string} value */
function safeArtifactDirectory(value) {
  const target = resolve(root, value);
  if (target !== releaseRoot && !target.startsWith(`${releaseRoot}${sep}`)) {
    throw new Error("Release artifacts must stay under artifacts/release");
  }
  return target;
}

/** @param {string} command @param {string[]} args @param {string} cwd */
function run(command, args, cwd) {
  const pnpmCli = command === "pnpm" ? pnpmCliCandidates[0] : undefined;
  const executable = pnpmCli ? process.execPath : command;
  const commandArgs = pnpmCli ? [pnpmCli, ...args] : args;
  const result = spawnSync(executable, commandArgs, { cwd, encoding: "utf8", shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${String(result.stderr).trim()}`);
  }
  return String(result.stdout);
}

/** @param {Buffer} value */
function tarText(value) {
  const end = value.indexOf(0);
  return value.subarray(0, end === -1 ? value.length : end).toString("utf8");
}

/** @param {Buffer} value */
function tarSize(value) {
  const text = tarText(value).trim();
  if (text === "") return 0;
  if (!/^[0-7]+$/.test(text)) throw new Error("Release tarball contains an invalid TAR size");
  const parsed = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error("Release tarball contains an unsafe TAR size");
  }
  return parsed;
}

/** @param {string} tarball */
function tarEntries(tarball) {
  const compressed = readFileSync(tarball);
  if (compressed.length > 10_000_000) {
    throw new Error("Release tarball exceeds the 10 MiB audit bound");
  }
  const archive = gunzipSync(compressed, { maxOutputLength: 50_000_000 });
  const entries = new Map();
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = tarText(header.subarray(0, 100));
    const prefix = tarText(header.subarray(345, 500));
    const path = prefix ? `${prefix}/${name}` : name;
    const size = tarSize(header.subarray(124, 136));
    const contentStart = offset + 512;
    const paddedSize = Math.ceil(size / 512) * 512;
    const nextOffset = contentStart + paddedSize;
    if (!path || nextOffset > archive.length) {
      throw new Error("Release tarball contains a truncated TAR entry");
    }
    if (entries.has(path)) throw new Error("Release tarball contains duplicate TAR entries");
    entries.set(path, archive.subarray(contentStart, contentStart + size));
    offset = nextOffset;
  }
  if (entries.size === 0) throw new Error("Release tarball contains no entries");
  return entries;
}

/** @param {string} tarball */
function packedManifest(tarball) {
  const entry = tarEntries(tarball).get("package/package.json");
  if (!entry) throw new Error("Release tarball is missing package/package.json");
  try {
    return asRecord(JSON.parse(entry.toString("utf8")));
  } catch {
    throw new Error("Release tarball package manifest is invalid JSON");
  }
}

/** @param {Record<string, unknown>} manifest @param {string} group */
function manifestDependencies(manifest, group) {
  const value = manifest[group];
  if (value === undefined) return {};
  const record = asRecord(value);
  return Object.fromEntries(
    Object.entries(record).map(([name, specifier]) => {
      if (typeof specifier !== "string") {
        throw new Error(`Packed ${group} entry must be a string`);
      }
      return [name, specifier];
    }),
  );
}

/** @param {Record<string, unknown>} manifest @param {string} packageName @param {string} expectedVersion */
export function validatePackedManifest(manifest, packageName, expectedVersion) {
  if (manifest.name !== packageName || manifest.version !== expectedVersion) {
    throw new Error(`${packageName} packed manifest identity does not match the release candidate`);
  }
  const dependencies = manifestDependencies(manifest, "dependencies");
  const optionalDependencies = manifestDependencies(manifest, "optionalDependencies");
  const peerDependencies = manifestDependencies(manifest, "peerDependencies");
  for (const specifier of [
    ...Object.values(dependencies),
    ...Object.values(optionalDependencies),
    ...Object.values(peerDependencies),
  ]) {
    if (/^(?:workspace|file|link):/i.test(specifier)) {
      throw new Error(
        `${packageName} packed manifest contains a non-publishable dependency specifier`,
      );
    }
  }
  for (const dependencyGroup of [dependencies, optionalDependencies, peerDependencies]) {
    for (const [name, specifier] of Object.entries(dependencyGroup)) {
      if (!name.startsWith(packageScope)) continue;
      if (!publishedPackageSpecifiers.has(name) || specifier !== expectedVersion) {
        throw new Error(
          packageName +
            " packed manifest contains an internal dependency outside the exact release set",
        );
      }
    }
  }
  return { dependencies, optionalDependencies, peerDependencies };
}

/** @param {string} specifier */
function installedVersion(specifier) {
  const candidates = [
    resolve(root, "node_modules", ...specifier.split("/"), "package.json"),
  ].concat(
    packageNames.map((packageName) =>
      resolve(
        root,
        "packages",
        packageName,
        "node_modules",
        ...specifier.split("/"),
        "package.json",
      ),
    ),
  );
  const metadataPath = candidates.find((candidate) => existsSync(candidate));
  if (!metadataPath) return "unresolved";
  const parsed = JSON.parse(readFileSync(metadataPath, "utf8"));
  return typeof parsed.version === "string" ? parsed.version : "unresolved";
}

/** @param {unknown} value */
function asRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected an object");
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {unknown} bom */
export function validateCycloneDxBom(bom) {
  const document = asRecord(bom);
  if (
    document.bomFormat !== "CycloneDX" ||
    document.specVersion !== "1.7" ||
    document.version !== 1
  ) {
    throw new Error("SBOM must be a CycloneDX 1.7 document");
  }
  if (
    typeof document.serialNumber !== "string" ||
    !/^urn:uuid:[0-9a-f-]{36}$/i.test(document.serialNumber)
  ) {
    throw new Error("SBOM serialNumber must be a UUID URN");
  }
  if (!Array.isArray(document.components) || document.components.length < packageNames.length) {
    throw new Error("SBOM must describe every published package");
  }
  for (const component of document.components) {
    const item = asRecord(component);
    if (
      item.type !== "library" ||
      typeof item.name !== "string" ||
      typeof item.version !== "string" ||
      typeof item.purl !== "string"
    ) {
      throw new Error("SBOM component is incomplete");
    }
  }
  if (!Array.isArray(document.dependencies)) throw new Error("SBOM dependencies must be an array");
  return true;
}

/** @param {string} value */
function uuidFrom(value) {
  const hash = sha256(value);
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

/** @param {string} name */
function npmPurl(name, version) {
  return `pkg:npm/${encodeURIComponent(name)}@${version}`;
}

/** @param {{ name: string, version: string, dependencies: Record<string, string>, optionalDependencies: Record<string, string>, peerDependencies: Record<string, string>, tarball: string, hash: string }[]} packages */
function createSbom(packages) {
  const externalScopes = new Map();
  for (const packageInfo of packages) {
    for (const dependencyName of Object.keys(packageInfo.dependencies)) {
      if (!dependencyName.startsWith(packageScope)) externalScopes.set(dependencyName, "required");
    }
    for (const dependencyName of Object.keys(packageInfo.optionalDependencies)) {
      if (!dependencyName.startsWith(packageScope) && !externalScopes.has(dependencyName)) {
        externalScopes.set(dependencyName, "optional");
      }
    }
    for (const dependencyName of Object.keys(packageInfo.peerDependencies)) {
      if (!dependencyName.startsWith(packageScope) && !externalScopes.has(dependencyName)) {
        externalScopes.set(dependencyName, "optional");
      }
    }
  }
  const externalComponents = [...externalScopes.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, scope]) => {
      const version = installedVersion(name);
      if (version === "unresolved")
        throw new Error(`Installed runtime dependency ${name} is unavailable for SBOM generation`);
      return { type: "library", name, version, purl: npmPurl(name, version), scope };
    });
  const components = packages
    .map((packageInfo) => ({
      type: "library",
      name: packageInfo.name,
      version: packageInfo.version,
      purl: npmPurl(packageInfo.name, packageInfo.version),
      hashes: [{ alg: "SHA-256", content: packageInfo.hash }],
      licenses: [{ license: { id: "Apache-2.0" } }],
    }))
    .concat(externalComponents);
  const dependencies = packages.map((packageInfo) => ({
    ref: npmPurl(packageInfo.name, packageInfo.version),
    dependsOn: [
      ...Object.keys(packageInfo.dependencies),
      ...Object.keys(packageInfo.optionalDependencies),
      ...Object.keys(packageInfo.peerDependencies),
    ]
      .map((name) =>
        name.startsWith(packageScope)
          ? npmPurl(
              name,
              packages.find((candidate) => candidate.name === name)?.version ?? "unresolved",
            )
          : npmPurl(name, installedVersion(name)),
      )
      .sort(),
  }));
  const identity = packages
    .map((packageInfo) => `${packageInfo.name}@${packageInfo.version}:${packageInfo.hash}`)
    .join("|");
  return {
    $schema: "https://cyclonedx.org/schema/bom-1.7.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: `urn:uuid:${uuidFrom(identity)}`,
    version: 1,
    metadata: {
      component: {
        type: "application",
        name: "openagentfence-release",
        version: packages[0]?.version ?? "0.0.0",
        licenses: [{ license: { id: "Apache-2.0" } }],
      },
    },
    components,
    dependencies,
  };
}

/** @param {string[]} files @param {Record<string, unknown>} manifest @param {string} packageName */
export function validatePackedFiles(files, manifest, packageName) {
  const declaredFiles = Array.isArray(manifest.files)
    ? manifest.files.filter((entry) => typeof entry === "string")
    : [];
  const allowedExact = new Set([
    "LICENSE",
    "NOTICE",
    "README.md",
    "package.json",
    ...declaredFiles.filter((file) => /\.[A-Za-z0-9]+$/u.test(file)),
  ]);
  const allowedPrefixes = declaredFiles
    .filter((file) => !/\.[A-Za-z0-9]+$/u.test(file))
    .map((file) => `${file.replace(/\/+$/, "")}/`);
  const unsafe =
    /(^|\/)(?:src|test|tests|fixtures|node_modules)(?:\/|$)|(^|\/)(?:package-lock\.json|pnpm-lock\.yaml|\.npmrc)$|\.(?:map|env|pem|key|p12|pfx)$/i;
  for (const file of files) {
    const declared =
      allowedExact.has(file) || allowedPrefixes.some((prefix) => file.startsWith(prefix));
    const explicitlyPublishedSchema = file.startsWith("src/schemas/") && allowedExact.has(file);
    if (!declared || (unsafe.test(file) && !explicitlyPublishedSchema)) {
      throw new Error(
        `${packageName} tarball contains a path outside its declared publish allowlist: ${file}`,
      );
    }
  }
  for (const legalFile of ["LICENSE", "NOTICE"]) {
    if (!files.includes(legalFile)) throw new Error(`Package tarball is missing ${legalFile}`);
  }
}

/** @param {string} tarball @param {string} packageName */
export function scanPackedContent(tarball, packageName) {
  const compressed = readFileSync(tarball);
  if (compressed.length > 10_000_000) {
    throw new Error("Release tarball exceeds the 10 MiB audit bound");
  }
  const content = gunzipSync(compressed, { maxOutputLength: 50_000_000 }).toString("latin1");
  const credentialPatterns = [
    ["aws-access-key", /AKIA[0-9A-Z]{16}/],
    ["private-key", /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/]{32,}\r?\n){2}/],
    ["named-token", /(?:npm|github|openai)[_-](?:token|key)\s*[:=]\s*[A-Za-z0-9_/-]{16,}/i],
    ["github-token", /github_pat_[A-Za-z0-9_]{20,}/],
  ];
  for (const [label, pattern] of credentialPatterns) {
    if (pattern.test(content))
      throw new Error(`${packageName} tarball contains a ${label} credential-like value`);
  }
}

/** @param {string[]} args */
function parseArgs(args) {
  let output = "artifacts/release";
  let expectedVersion;
  let requirePublishable = false;
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (value === "--out") {
      output = args[index + 1] ?? "";
      index += 1;
    } else if (value === "--version") {
      expectedVersion = args[index + 1] ?? "";
      index += 1;
    } else if (value === "--require-publishable") {
      requirePublishable = true;
    } else {
      throw new Error(
        "Usage: node scripts/release-artifacts.mjs [--out artifacts/release] [--version x.y.z] [--require-publishable]",
      );
    }
  }
  if (
    requirePublishable &&
    (!expectedVersion || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(expectedVersion))
  ) {
    throw new Error("--require-publishable requires an exact SemVer --version");
  }
  return { output: safeArtifactDirectory(output), expectedVersion, requirePublishable };
}

export function main(args = process.argv.slice(2), workspaceRoot = root) {
  const { output, expectedVersion, requirePublishable } = parseArgs(args);
  rmSync(output, { recursive: true, force: true });
  mkdirSync(resolve(output, "packages"), { recursive: true });
  const packageInfos = [];
  for (const packageName of packageNames) {
    const packageDirectory = resolve(workspaceRoot, "packages", packageName);
    const manifest = asRecord(
      JSON.parse(readFileSync(resolve(packageDirectory, "package.json"), "utf8")),
    );
    const name = String(manifest.name);
    const version = String(manifest.version);
    if (
      !name.startsWith(packageScope) ||
      !Array.isArray(manifest.files) ||
      !manifest.files.includes("LICENSE") ||
      !manifest.files.includes("NOTICE")
    ) {
      throw new Error(`${packageName} must declare its scoped package identity and legal files`);
    }
    if (requirePublishable && (version !== expectedVersion || version === "0.0.0")) {
      throw new Error(`${name} is not publishable at ${expectedVersion}`);
    }
    const packageOutput = resolve(output, "packages", packageName);
    mkdirSync(packageOutput, { recursive: true });
    const raw = run(
      "pnpm",
      ["pack", "--json", "--pack-destination", packageOutput],
      packageDirectory,
    );
    const packOutput = JSON.parse(raw);
    const entry = asRecord(
      Array.isArray(packOutput) ? (packOutput.length === 1 ? packOutput[0] : null) : packOutput,
    );
    const files = Array.isArray(entry.files)
      ? entry.files.map((file) => String(asRecord(file).path))
      : [];
    const tarball = resolve(packageOutput, String(entry.filename));
    if (!existsSync(tarball) || statSync(tarball).size === 0)
      throw new Error(`${name} tarball was not created`);
    const packed = packedManifest(tarball);
    const packedDependencies = validatePackedManifest(packed, name, version);
    validatePackedFiles(files, manifest, name);
    scanPackedContent(tarball, name);
    packageInfos.push({
      name,
      version,
      dependencies: packedDependencies.dependencies,
      optionalDependencies: packedDependencies.optionalDependencies,
      peerDependencies: packedDependencies.peerDependencies,
      tarball: tarball.slice(root.length + 1).replaceAll("\\", "/"),
      hash: sha256File(tarball),
      files,
    });
  }
  const sbom = createSbom(packageInfos);
  validateCycloneDxBom(sbom);
  writeFileSync(
    resolve(output, "openagentfence.cdx.json"),
    `${JSON.stringify(sbom, null, 2)}\n`,
    "utf8",
  );
  const audit = {
    format: "openagentfence-release-artifact-audit-v1",
    packages: packageInfos.map(({ files, ...packageInfo }) => ({ ...packageInfo, files })),
    sbom: "openagentfence.cdx.json",
  };
  writeFileSync(
    resolve(output, "package-audit.json"),
    `${JSON.stringify(audit, null, 2)}\n`,
    "utf8",
  );
  process.stdout.write(
    `created ${packageInfos.length} package tarballs and CycloneDX SBOM at ${output.slice(root.length + 1)}\n`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
