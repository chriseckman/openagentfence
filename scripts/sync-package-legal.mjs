import { readFileSync, writeFileSync } from "node:fs";
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
const write = process.argv.slice(2).join(" ") === "--write";

if (process.argv.length > 3 && !write) {
  throw new Error("Usage: node scripts/sync-package-legal.mjs [--write]");
}

for (const fileName of ["LICENSE", "NOTICE"]) {
  const source = readFileSync(resolve(root, fileName), "utf8");
  for (const packageName of packageNames) {
    const target = resolve(root, "packages", packageName, fileName);
    let current;
    try {
      current = readFileSync(target, "utf8");
    } catch {
      current = undefined;
    }
    if (current === source) continue;
    if (!write) {
      throw new Error(`${target} must match the repository ${fileName}; run pnpm legal:sync`);
    }
    writeFileSync(target, source, "utf8");
  }
}

process.stdout.write(`${write ? "synchronized" : "verified"} package LICENSE and NOTICE files\n`);
