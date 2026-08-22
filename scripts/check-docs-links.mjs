// Documentation link and anchor check.
//
// Verifies that every relative Markdown link in the repository resolves to an
// existing file and that local Markdown fragments resolve to a heading or an
// explicit HTML anchor. Run via `pnpm docs:check`. This backs the CI "docs"
// job and the review contract in docs/DOC_REVIEW_PROMPT.md (OAF-REPO-004).

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
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
    if (entry.isDirectory()) walk(path, acc);
    else if (extname(entry.name) === ".md") acc.push(path);
  }
  return acc;
}

/**
 * Create a GitHub-compatible safe anchor from a Markdown heading.
 * HTML markup is skipped structurally: no attacker-controlled tag text can
 * enter the returned anchor, including when the tag is malformed/unclosed.
 *
 * @param {string} heading
 */
export function slugifyHeading(heading) {
  let slug = "";
  let inHtmlTag = false;
  for (const character of heading.trim().toLowerCase()) {
    if (inHtmlTag) {
      if (character === ">") inHtmlTag = false;
      continue;
    }
    if (character === "<") {
      inHtmlTag = true;
      continue;
    }
    if (character === "`" || character === "*" || character === "_" || character === "~") {
      continue;
    }
    if (character === "-" || /[\p{L}\p{N}]/u.test(character)) {
      slug += character;
      continue;
    }
    // GitHub replaces each remaining whitespace character; punctuation
    // between two spaces therefore produces the intentional `--` seen in
    // headings such as "M0 — Repository".
    if (/\s/u.test(character)) slug += "-";
  }
  return slug;
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

export function main() {
  const files = [];
  walk(ROOT, files);
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
      if (
        encodedFragment !== undefined &&
        encodedFragment.length > 0 &&
        extname(target) === ".md"
      ) {
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

  if (broken > 0) process.exitCode = 1;
  else console.log(`docs link and anchor check passed (${files.length} files)`);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main();
