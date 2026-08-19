// Minimal documentation link check.
//
// Verifies that every relative Markdown link in the repository resolves to an
// existing file (anchors and external URLs are ignored). Run via
// `pnpm docs:check`. This backs the CI "docs" job (OAF-REPO-004).

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname, extname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function walk(dir, acc = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") {
      continue;
    }
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(path, acc);
    } else if (extname(entry.name) === ".md") {
      acc.push(path);
    }
  }
  return acc;
}

const files = [];
walk(join(ROOT, "docs"), files);
for (const entry of readdirSync(ROOT)) {
  if (extname(entry) === ".md") {
    files.push(join(ROOT, entry));
  }
}

let broken = 0;
for (const file of files) {
  const text = readFileSync(file, "utf8");
  const linkRe = /\]\(([^)]+)\)/g;
  let match;
  while ((match = linkRe.exec(text)) !== null) {
    const link = match[1];
    if (
      link.startsWith("http://") ||
      link.startsWith("https://") ||
      link.startsWith("#") ||
      link.startsWith("mailto:")
    ) {
      continue;
    }
    const [pathPart] = link.split("#");
    if (!pathPart) {
      continue;
    }
    const target = join(dirname(file), pathPart);
    if (!existsSync(target)) {
      console.error(`broken link in ${relative(ROOT, file)}: ${link}`);
      broken += 1;
    }
  }
}

if (broken > 0) {
  process.exit(1);
}
console.log(`docs link check passed (${files.length} files)`);
