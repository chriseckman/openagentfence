// Generate/refresh API report baselines for every public package.
//
// Requires `pnpm build` to have produced `dist/index.d.ts` for each package.
// Uses `--local` so the report files under `packages/<name>/etc` are written
// in place. Run via `pnpm api-report`.

import { readdirSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES_DIR = join(ROOT, "packages");
const API_EXTRACTOR_BIN = join(
  ROOT,
  "node_modules",
  "@microsoft",
  "api-extractor",
  "bin",
  "api-extractor",
);

// `--local` writes the report baselines in place. Without it, api-extractor
// fails when the committed baseline differs from the current public API.
const check = process.argv.includes("--check");

for (const dir of readdirSync(PACKAGES_DIR).sort()) {
  const config = join(PACKAGES_DIR, dir, "api-extractor.json");
  if (!existsSync(config)) {
    continue;
  }
  process.stdout.write(`api-report${check ? " (check)" : ""}: @openagentfence/${dir}\n`);
  mkdirSync(join(PACKAGES_DIR, dir, "etc"), { recursive: true });
  const args = [API_EXTRACTOR_BIN, "run", "--config", config];
  if (!check) {
    args.splice(2, 0, "--local");
  }
  execFileSync(process.execPath, args, { stdio: "inherit" });
}
