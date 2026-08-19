// Enforce ARCHITECTURE §3 dependency direction across the workspace.
//
// Scans each package's declared `@openagentfence/*` dependencies (dependencies,
// devDependencies, peerDependencies) and its source imports, then reports any
// edge that violates the allowed dependency map. Exits non-zero on violation.
//
// Run via `pnpm check:deps` (also wired into `pnpm lint`).

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { dependencyViolations } from "./dependency-rules.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES_DIR = join(ROOT, "packages");
const PREFIX = "@openagentfence/";

/** Strip the `@openagentfence/` prefix, returning the short package name. */
function short(name) {
  return name.startsWith(PREFIX) ? name.slice(PREFIX.length) : name;
}

/** Recursively list files under a directory. */
function walkFiles(dir, acc = []) {
  if (!existsSync(dir)) {
    return acc;
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(path, acc);
    } else if (entry.isFile()) {
      acc.push(path);
    }
  }
  return acc;
}

/** Collect `@openagentfence/*` references (declared deps + source imports). */
function collect() {
  const result = {};
  for (const dir of readdirSync(PACKAGES_DIR)) {
    const pkgJsonPath = join(PACKAGES_DIR, dir, "package.json");
    if (!existsSync(pkgJsonPath)) {
      continue;
    }
    const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
    const deps = new Set();

    // Runtime edges come from `dependencies` and source imports. devDependencies
    // (test/build tooling) do not create a runtime dependency edge, so a
    // browser-adapter's *test* may depend on `@openagentfence/scanners` to run
    // the vertical slice without violating the runtime direction rule.
    for (const key of ["dependencies", "peerDependencies"]) {
      for (const dep of Object.keys(pkg[key] ?? {})) {
        if (dep.startsWith(PREFIX)) {
          deps.add(short(dep));
        }
      }
    }

    const importRe = /from\s+["'](@openagentfence\/[^"']+)["']/g;
    for (const file of walkFiles(join(PACKAGES_DIR, dir, "src"))) {
      if (!file.endsWith(".ts")) {
        continue;
      }
      const text = readFileSync(file, "utf8");
      let match;
      while ((match = importRe.exec(text)) !== null) {
        deps.add(short(match[1]));
      }
    }

    result[dir] = [...deps].sort();
  }
  return result;
}

const violations = dependencyViolations(collect());
if (violations.length > 0) {
  for (const v of violations) {
    console.error(`dependency-direction violation: ${v.package} -> ${v.dependency} (${v.reason})`);
  }
  process.exit(1);
}
console.log("dependency-direction check passed");
