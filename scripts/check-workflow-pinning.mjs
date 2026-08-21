import { readdir, readFile } from "node:fs/promises";

const workflowDirectory = new URL("../.github/workflows/", import.meta.url);
const workflowFiles = (await readdir(workflowDirectory))
  .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
  .sort();
if (workflowFiles.length === 0) throw new Error("no GitHub workflows found to validate");
const workflowDocuments = await Promise.all(
  workflowFiles.map(async (file) => ({
    file,
    text: await readFile(new URL(file, workflowDirectory), "utf8"),
  })),
);
const workflow = workflowDocuments.find((document) => document.file === "ci.yml")?.text;
if (workflow === undefined) throw new Error("CI workflow is missing");
const nightly = await readFile(
  new URL("../.github/workflows/property-fuzz-nightly.yml", import.meta.url),
  "utf8",
);
const benchmarkNightly = await readFile(
  new URL("../.github/workflows/benchmark-nightly.yml", import.meta.url),
  "utf8",
);
const uses = [
  ...workflowDocuments.flatMap((document) => [
    ...document.text.matchAll(/^\s*- uses: ([^\s]+)$/gm),
  ]),
].map((match) => match[1]);

if (uses.length === 0) throw new Error("GitHub workflows contain no actions to validate");
for (const action of uses) {
  if (action === undefined || !/@[0-9a-f]{40}$/i.test(action)) {
    throw new Error(`GitHub workflow action is not pinned by a full SHA: ${action ?? "<missing>"}`);
  }
}

const integration = workflow.match(/\n  integration:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (integration === null) throw new Error("CI workflow is missing the integration job");
if (/^\s*if:\s*false\s*$/m.test(integration[1] ?? "")) {
  throw new Error("CI integration job must not be disabled");
}
if (!/playwright install --with-deps chromium/.test(integration[1] ?? "")) {
  throw new Error("CI integration job does not install Chromium deterministically");
}

const corpus = workflow.match(/\n  security-corpus:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (corpus === null) throw new Error("CI workflow is missing the security-corpus job");
if (/^\s*if:\s*false\s*$/m.test(corpus[1] ?? "")) {
  throw new Error("CI security-corpus job must not be disabled");
}
if (!/@openagentfence\/testing test/.test(corpus[1] ?? "")) {
  throw new Error("CI security-corpus job does not validate the corpus contract");
}
if (!/pnpm test:corpus/.test(corpus[1] ?? "")) {
  throw new Error("CI security-corpus job does not execute the published corpus CLI gate");
}
if (!/playwright install --with-deps chromium/.test(corpus[1] ?? "")) {
  throw new Error("CI security-corpus job does not install Chromium deterministically");
}
if (!/actions\/upload-artifact@[0-9a-f]{40}/.test(corpus[1] ?? "")) {
  throw new Error("CI security-corpus job does not retain a safe regression artifact");
}

const invariants = workflow.match(/\n  invariants:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (invariants === null) throw new Error("CI workflow is missing the security invariants job");
if (/^\s*if:\s*false\s*$/m.test(invariants[1] ?? "")) {
  throw new Error("CI security invariants job must not be disabled");
}
if (!/pnpm test:invariants/.test(invariants[1] ?? "")) {
  throw new Error("CI security invariants job does not run INV-01 through INV-21");
}

const promptfoo = workflow.match(/\n  promptfoo-example:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (promptfoo === null) throw new Error("CI workflow is missing the Promptfoo example job");
if (/^\s*if:\s*false\s*$/m.test(promptfoo[1] ?? "")) {
  throw new Error("CI Promptfoo example job must not be disabled");
}
if (!/node-version:\s*24/.test(promptfoo[1] ?? "")) {
  throw new Error("CI Promptfoo example job must use a supported Node version");
}
if (!/pnpm promptfoo:check/.test(promptfoo[1] ?? "")) {
  throw new Error("CI Promptfoo example job does not run the offline gate");
}

const property = workflow.match(/\n  property-fuzz:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (property === null || !/pnpm test:property/.test(property[1] ?? "")) {
  throw new Error("CI is missing the required 1,000-run property gate");
}
if (!/schedule:/.test(nightly) || !/OAF_PROPERTY_RUNS:\s*"10000"/.test(nightly)) {
  throw new Error("nightly property workflow is missing its bounded 10,000-run schedule");
}
if (!/pnpm test:property/.test(nightly)) {
  throw new Error("nightly property workflow does not run the property gate");
}

const benchmark = workflow.match(/\n  benchmark-smoke:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (benchmark === null || !/pnpm benchmark:pr/.test(benchmark[1] ?? "")) {
  throw new Error("CI is missing the required offline benchmark smoke gate");
}
if (
  !/schedule:/.test(benchmarkNightly) ||
  !/OAF_BENCHMARK_PROFILE:\s*nightly/.test(benchmarkNightly)
) {
  throw new Error("nightly benchmark workflow is missing its bounded schedule/profile");
}
if (!/pnpm benchmark:pr/.test(benchmarkNightly)) {
  throw new Error("nightly benchmark workflow does not run the offline scripted benchmark");
}

console.log(
  "workflow pinning, Chromium integration, executable corpus, invariants, Promptfoo, benchmark, and property/fuzz checks passed",
);
