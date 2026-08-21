import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { promptfooOfflineEnvironment } from "./promptfoo-offline-environment.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = await mkdtemp(join(tmpdir(), "openagentfence-promptfoo-"));
const promptfooCli = resolve(
  repositoryRoot,
  "node_modules",
  "promptfoo",
  "dist",
  "src",
  "entrypoint.js",
);
const tscCli = resolve(repositoryRoot, "node_modules", "typescript", "bin", "tsc");
const config = resolve(repositoryRoot, "examples/promptfoo/promptfooconfig.yaml");
const promptfooPackage = JSON.parse(
  await readFile(resolve(repositoryRoot, "node_modules/promptfoo/package.json"), "utf8"),
);
if (promptfooPackage.version !== "0.122.0") {
  throw new Error("Promptfoo example requires the pinned 0.122.0 development tool");
}
const env = promptfooOfflineEnvironment(process.env, {
  configDirectory: temporaryRoot,
  logDirectory: join(temporaryRoot, "logs"),
});

try {
  await mkdir(env.PROMPTFOO_LOG_DIR, { recursive: true });
  await run(process.execPath, [tscCli, "-p", "examples/tsconfig.json"], env);
  await run(process.execPath, [promptfooCli, "validate", "config", "-c", config], env);
  await run(
    process.execPath,
    [
      promptfooCli,
      "eval",
      "-c",
      config,
      "--no-write",
      "--no-share",
      "--no-cache",
      "--max-concurrency",
      "1",
    ],
    env,
  );
  process.stdout.write("Promptfoo 0.122.0 offline example check passed\n");
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

function run(command, args, childEnv) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: repositoryRoot,
      env: childEnv,
      stdio: "inherit",
      shell: false,
      windowsHide: true,
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolveRun();
        return;
      }
      rejectRun(
        new Error(
          `promptfoo example command failed (${command}, exit=${String(code)}, signal=${String(signal)})`,
        ),
      );
    });
  });
}
