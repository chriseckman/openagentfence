// Documentation link and anchor check.
//
// Verifies that every relative Markdown link in the repository resolves to an
// existing file and that local Markdown fragments resolve to a heading or an
// explicit HTML anchor. Run via `pnpm docs:check`. This backs the CI "docs"
// job and the review contract in docs/DOC_REVIEW_PROMPT.md (OAF-REPO-004).

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname, extname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function walk(dir, acc = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (
      entry.name === "node_modules" ||
      entry.name === ".git" ||
      entry.name === ".opencode" ||
      entry.name === "dist" ||
      entry.name === "coverage" ||
      entry.name === "artifacts" ||
      entry.name === ".turbo"
    ) {
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
walk(ROOT, files);

function slugifyHeading(heading) {
  return (
    heading
      .trim()
      .toLowerCase()
      .replace(/<[^>]*>/g, "")
      .replace(/[`*_~]/g, "")
      .replace(/[^\p{L}\p{N}\s-]/gu, "")
      // GitHub replaces each remaining whitespace character; punctuation
      // between two spaces therefore produces the intentional `--` seen in
      // headings such as "M0 — Repository".
      .replace(/\s/g, "-")
  );
}

function anchorsFor(file) {
  const text = readFileSync(file, "utf8");
  const anchors = new Set();
  const duplicates = new Map();
  let inFence = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const heading = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading?.[2] !== undefined) {
      const base = slugifyHeading(heading[2]);
      if (base.length > 0) {
        const count = duplicates.get(base) ?? 0;
        anchors.add(count === 0 ? base : `${base}-${count}`);
        duplicates.set(base, count + 1);
      }
    }
    for (const match of line.matchAll(/<a\s+(?:name|id)=["']([^"']+)["'][^>]*>/gi)) {
      if (match[1] !== undefined) anchors.add(match[1]);
    }
  }
  return anchors;
}

const anchorsByFile = new Map(files.map((file) => [file, anchorsFor(file)]));

let broken = 0;
for (const file of files) {
  const text = readFileSync(file, "utf8");
  const linkRe = /\]\(([^)]+)\)/g;
  let match;
  while ((match = linkRe.exec(text)) !== null) {
    const link = match[1];
    if (link.startsWith("http://") || link.startsWith("https://") || link.startsWith("mailto:")) {
      continue;
    }
    const [pathPart = "", encodedFragment] = link.split("#", 2);
    const target = pathPart.length === 0 ? file : join(dirname(file), pathPart);
    if (!existsSync(target)) {
      console.error(`broken link in ${relative(ROOT, file)}: ${link}`);
      broken += 1;
      continue;
    }
    if (encodedFragment !== undefined && encodedFragment.length > 0 && extname(target) === ".md") {
      let fragment;
      try {
        fragment = decodeURIComponent(encodedFragment);
      } catch {
        console.error(`invalid link fragment in ${relative(ROOT, file)}: ${link}`);
        broken += 1;
        continue;
      }
      const targetAnchors = anchorsByFile.get(target) ?? anchorsFor(target);
      if (!targetAnchors.has(fragment)) {
        console.error(`broken anchor in ${relative(ROOT, file)}: ${link}`);
        broken += 1;
      }
    }
  }
}

if (broken > 0) {
  process.exit(1);
}
console.log(`docs link and anchor check passed (${files.length} files)`);
