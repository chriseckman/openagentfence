import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
const buildScript = resolve(root, "scripts", "build-package.mjs");
const requestedPackages = process.argv.slice(2);
const selectedPackages = requestedPackages.length === 0 ? packageNames : requestedPackages;

for (const packageName of selectedPackages) {
  if (!packageNames.includes(packageName)) {
    throw new Error(`Unknown publishable package: ${packageName}`);
  }
}

for (const packageName of selectedPackages) {
  const result = spawnSync(process.execPath, [buildScript], {
    cwd: resolve(root, "packages", packageName),
    stdio: "inherit",
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

process.stdout.write(
  `built ${selectedPackages.length} publishable package(s) without source maps\n`,
);
