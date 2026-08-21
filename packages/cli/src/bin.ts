#!/usr/bin/env node

import { runCorpusCommand } from "./commands/corpus.js";
import { runDoctorCommand } from "./commands/doctor.js";
import { runExplainCommand } from "./commands/explain.js";
import { runInitCommand } from "./commands/init.js";
import { runPolicyValidateCommand } from "./commands/policy.js";
import { createPlaywrightCorpusExecutor } from "./commands/playwright-corpus.js";

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  const io = {
    stdout: (text: string) => process.stdout.write(text),
    stderr: (text: string) => process.stderr.write(text),
  };
  if (command === "test") {
    process.exitCode = await runCorpusCommand(
      args,
      { ...io, ci: process.env["CI"] === "true" },
      { createExecutor: createPlaywrightCorpusExecutor },
    );
    return;
  }
  if (command === "init") {
    process.exitCode = await runInitCommand(args, io);
    return;
  }
  if (command === "doctor") {
    process.exitCode = await runDoctorCommand(args, io);
    return;
  }
  if (command === "explain") {
    process.exitCode = await runExplainCommand(args, io);
    return;
  }
  if (command === "policy" && args[0] === "validate") {
    process.exitCode = await runPolicyValidateCommand(args.slice(1), io);
    return;
  }
  process.stderr.write("usage: openagentfence <init|doctor|test|explain|policy validate>\n");
  process.exitCode = 2;
}

void main();
