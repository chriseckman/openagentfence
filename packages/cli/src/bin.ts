#!/usr/bin/env node

import { runCorpusCommand } from "./commands/corpus.js";
import { createPlaywrightCorpusExecutor } from "./commands/playwright-corpus.js";

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command !== "test") {
    process.stderr.write("usage: openagentfence test --corpus <directory|manifest>\n");
    process.exitCode = 2;
    return;
  }
  process.exitCode = await runCorpusCommand(
    args,
    {
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
      ci: process.env["CI"] === "true",
    },
    { createExecutor: createPlaywrightCorpusExecutor },
  );
}

void main();
