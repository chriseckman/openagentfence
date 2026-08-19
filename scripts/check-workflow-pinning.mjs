import { readFile } from "node:fs/promises";

const workflow = await readFile(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const uses = [...workflow.matchAll(/^\s*- uses: ([^\s]+)$/gm)].map((match) => match[1]);

if (uses.length === 0) throw new Error("CI workflow contains no actions to validate");
for (const action of uses) {
  if (action === undefined || !/@[0-9a-f]{40}$/i.test(action)) {
    throw new Error(`CI action is not pinned by a full SHA: ${action ?? "<missing>"}`);
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

console.log("workflow pinning and Chromium integration gate check passed");
