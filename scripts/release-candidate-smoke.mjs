import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const releaseRoot = resolve(root, "artifacts", "release");
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
const packageSpecifiers = packageNames.map((name) => `@openagentfence/${name}`);
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

/** @param {string} value */
function sha256File(value) {
  return createHash("sha256").update(readFileSync(value)).digest("hex");
}

/** @param {string[]} args */
function parseArgs(args) {
  let version;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--version" && version === undefined) {
      version = args[index + 1];
      index += 1;
      continue;
    }
    throw new Error("Usage: node scripts/release-candidate-smoke.mjs [--version x.y.z]");
  }
  if (version !== undefined && !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(version)) {
    throw new Error("Release candidate smoke requires an exact SemVer version");
  }
  return version;
}

/** @param {string} command @param {string[]} args @param {string} cwd */
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed without exposing command output`);
  }
  return `${result.stdout}${result.stderr}`;
}

function npmCli() {
  const path = resolve(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (!existsSync(path)) throw new Error("Release candidate smoke requires the bundled npm CLI");
  return path;
}

function pnpmCommand() {
  const cli = pnpmCliCandidates[0];
  return cli === undefined
    ? { command: "pnpm", prefix: [] }
    : { command: process.execPath, prefix: [cli] };
}

/** @param {string} version */
function readAuditedTarballs(version) {
  const auditPath = resolve(releaseRoot, "package-audit.json");
  const sbomPath = resolve(releaseRoot, "openagentfence.cdx.json");
  if (!existsSync(auditPath) || !existsSync(sbomPath)) {
    throw new Error("Release candidate smoke requires freshly audited tarballs and SBOM");
  }
  const audit = JSON.parse(readFileSync(auditPath, "utf8"));
  const sbom = JSON.parse(readFileSync(sbomPath, "utf8"));
  if (!Array.isArray(audit.packages) || audit.packages.length !== packageNames.length) {
    throw new Error("Release package audit is incomplete");
  }
  if (!Array.isArray(sbom.components)) throw new Error("Release SBOM is incomplete");
  const tarballs = [];
  for (const packageName of packageNames) {
    const name = `@openagentfence/${packageName}`;
    const entry = audit.packages.find((candidate) => candidate?.name === name);
    if (
      !entry ||
      entry.version !== version ||
      typeof entry.tarball !== "string" ||
      typeof entry.hash !== "string"
    ) {
      throw new Error("Release package audit does not match the requested candidate version");
    }
    const tarball = resolve(root, entry.tarball);
    if (!tarball.startsWith(`${releaseRoot}\\`) && !tarball.startsWith(`${releaseRoot}/`)) {
      throw new Error("Release package audit refers outside the release-artifact directory");
    }
    if (!existsSync(tarball) || sha256File(tarball) !== entry.hash) {
      throw new Error("Release package tarball hash does not match its audit record");
    }
    const component = sbom.components.find(
      (candidate) => candidate?.name === name && candidate?.version === version,
    );
    const sbomHash = component?.hashes?.find((hash) => hash?.alg === "SHA-256")?.content;
    if (sbomHash !== entry.hash) throw new Error("Release SBOM does not match its package audit");
    tarballs.push(tarball);
  }
  return tarballs;
}

/** @param {string} temporaryRoot */
function packLocalYaml(temporaryRoot) {
  const yamlDirectory = resolve(
    root,
    "node_modules",
    ".pnpm",
    "yaml@2.9.0",
    "node_modules",
    "yaml",
  );
  if (!existsSync(yamlDirectory))
    throw new Error("Release candidate smoke requires installed yaml@2.9.0");
  const output = resolve(temporaryRoot, "dependencies");
  mkdirSync(output, { recursive: true });
  const pnpm = pnpmCommand();
  run(
    pnpm.command,
    [...pnpm.prefix, "pack", "--json", "--pack-destination", output],
    yamlDirectory,
  );
  const tarball = readdirSync(output).find((entry) => entry.endsWith(".tgz"));
  if (!tarball) throw new Error("Could not pack the required local yaml dependency");
  return resolve(output, tarball);
}

/** @param {string} temporaryRoot */
function writeSmokeImports(temporaryRoot) {
  const source = `import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
for (const specifier of ${JSON.stringify(packageSpecifiers)}) await import(specifier);
for (const specifier of [
  "@openagentfence/core/schemas/trace.schema.json",
  "@openagentfence/policy/schemas/openagentfence-policy.schema.json",
  "@openagentfence/testing/schemas/corpus-case.schema.json",
]) {
  const path = fileURLToPath(import.meta.resolve(specifier));
  JSON.parse(readFileSync(path, "utf8"));
}
`;
  writeFileSync(resolve(temporaryRoot, "imports.mjs"), source, "utf8");
}

/** @param {string} temporaryRoot */
function writeQuickStart(temporaryRoot) {
  const source = `import { OpenAgentFence, DEFAULT_NETWORK_CAPABILITIES } from "@openagentfence/core";
import { loadPolicy } from "@openagentfence/policy";
import { defaultScanners } from "@openagentfence/scanners";
const adapter = {
  capabilities: { route: false, network: DEFAULT_NETWORK_CAPABILITIES, navigationEvents: true, downloadEvents: true, popupEvents: true, screenshot: false, ariaSnapshot: false },
  observe: async () => ({ url: "https://example.test", origin: "https://example.test", frames: [], provenance: { trust: "web" } }),
  executeAuthorized: async () => undefined,
  subscribe: () => () => {},
  rawPage: () => ({ unavailable: true }),
};
const firewall = new OpenAgentFence({ adapter, policy: await loadPolicy("candidate.yml"), scanners: defaultScanners() });
const session = firewall.start({ task: "read a local fixture" });
if (!session.envelope.evaluate({ type: "READ" }).allowed || session.envelope.evaluate({ type: "UPLOAD" }).allowed) throw new Error("secure quick start envelope failed");
await session.end();
`;
  writeFileSync(resolve(temporaryRoot, "quick-start.mjs"), source, "utf8");
}

export function main(args = process.argv.slice(2)) {
  const expectedVersion = parseArgs(args);
  if (expectedVersion === undefined) throw new Error("Release candidate smoke requires --version");
  const tarballs = readAuditedTarballs(expectedVersion);
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), "openagentfence-rc-smoke-"));
  try {
    const yamlTarball = packLocalYaml(temporaryRoot);
    const dependencies = Object.fromEntries(
      packageSpecifiers.map((specifier, index) => [specifier, pathToFileURL(tarballs[index]).href]),
    );
    dependencies.yaml = pathToFileURL(yamlTarball).href;
    writeFileSync(
      resolve(temporaryRoot, "package.json"),
      `${JSON.stringify(
        {
          name: "openagentfence-release-candidate-smoke",
          private: true,
          type: "module",
          dependencies,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    run(
      process.execPath,
      [
        npmCli(),
        "install",
        "--offline",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--legacy-peer-deps",
        "--package-lock=false",
      ],
      temporaryRoot,
    );
    writeSmokeImports(temporaryRoot);
    run(process.execPath, [resolve(temporaryRoot, "imports.mjs")], temporaryRoot);
    const binary = resolve(
      temporaryRoot,
      "node_modules",
      "@openagentfence",
      "cli",
      "dist",
      "bin.js",
    );
    run(process.execPath, [binary, "init", "--path", "candidate.yml"], temporaryRoot);
    run(process.execPath, [binary, "policy", "validate", "candidate.yml"], temporaryRoot);
    run(process.execPath, [binary, "doctor", "--json"], temporaryRoot);
    writeQuickStart(temporaryRoot);
    run(process.execPath, [resolve(temporaryRoot, "quick-start.mjs")], temporaryRoot);
    process.stdout.write(
      `isolated install/import/CLI/quick-start smoke passed for ${expectedVersion}\n`,
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
