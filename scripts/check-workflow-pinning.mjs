import { readdir, readFile } from "node:fs/promises";

function normalizeNewlines(text) {
  return text.replace(/\r\n?/g, "\n");
}

const workflowDirectory = new URL("../.github/workflows/", import.meta.url);
const workflowFiles = (await readdir(workflowDirectory))
  .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
  .sort();
if (workflowFiles.length === 0) throw new Error("no GitHub workflows found to validate");
const workflowDocuments = await Promise.all(
  workflowFiles.map(async (file) => ({
    file,
    text: normalizeNewlines(await readFile(new URL(file, workflowDirectory), "utf8")),
  })),
);
const workflow = workflowDocuments.find((document) => document.file === "ci.yml")?.text;
if (workflow === undefined) throw new Error("CI workflow is missing");
const nightly = normalizeNewlines(
  await readFile(
    new URL("../.github/workflows/property-fuzz-nightly.yml", import.meta.url),
    "utf8",
  ),
);
const benchmarkNightly = normalizeNewlines(
  await readFile(new URL("../.github/workflows/benchmark-nightly.yml", import.meta.url), "utf8"),
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

const dco = workflow.match(/\n  dco:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (dco === null) throw new Error("CI workflow is missing the required DCO job");
const dcoJob = dco[1] ?? "";
if (!/fetch-depth:\s*0/.test(dcoJob)) {
  throw new Error("CI DCO job must fetch complete history before computing its range");
}
if (/git rev-list[^\n]*\|\|/.test(dcoJob)) {
  throw new Error("CI DCO job must fail closed when its commit range cannot be resolved");
}
if (!/git log[^\n]*Signed-off-by:/.test(dcoJob)) {
  throw new Error("CI DCO job must verify every commit has a Signed-off-by trailer");
}

const releaseCandidate = workflow.match(/\n  release-candidate:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (releaseCandidate === null) {
  throw new Error("CI workflow is missing the local release-candidate artifact audit");
}
const releaseCandidateJob = releaseCandidate[1] ?? "";
if (!/node-version:\s*24/.test(releaseCandidateJob)) {
  throw new Error("CI release-candidate audit must use the supported Node 24 runtime");
}
if (!/pnpm release:candidate/.test(releaseCandidateJob)) {
  throw new Error("CI release-candidate audit must create the staged candidate artifacts");
}
if (!/pnpm test:release-artifacts/.test(releaseCandidateJob)) {
  throw new Error("CI release-candidate audit must revalidate its packed artifacts");
}
if (!/actions\/upload-artifact@[0-9a-f]{40}/.test(releaseCandidateJob)) {
  throw new Error("CI release-candidate audit must retain its audited local artifacts");
}

const dependencyAudit = workflow.match(/\n  dependency-audit:\n([\s\S]*?)(?=\n  [a-z][\w-]*:|$)/);
if (dependencyAudit === null || !/pnpm audit:dependencies/.test(dependencyAudit[1] ?? "")) {
  throw new Error("CI is missing the required dependency advisory audit");
}

console.log(
  "workflow pinning, Chromium integration, executable corpus, invariants, Promptfoo, benchmark, and property/fuzz checks passed",
);
