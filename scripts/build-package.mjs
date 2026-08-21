import { existsSync, rmSync } from "node:fs";
import { resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageDirectory = resolve(process.cwd());
const packageRoot = resolve(root, "packages");
if (!packageDirectory.startsWith(`${packageRoot}${sep}`)) {
  throw new Error("Package builds must run from a workspace package directory");
}
const output = resolve(packageDirectory, "dist");
if (!output.startsWith(`${packageDirectory}${sep}`)) {
  throw new Error("Refusing to clean a package build path outside its package directory");
}
if (existsSync(output)) rmSync(output, { recursive: true, force: true });
const tsc = resolve(root, "node_modules", "typescript", "bin", "tsc");
const result = spawnSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], {
  cwd: packageDirectory,
  stdio: "inherit",
  shell: false,
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
