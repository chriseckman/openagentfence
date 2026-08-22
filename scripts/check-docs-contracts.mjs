// Source-backed release-documentation coverage check. The tables themselves
// receive prose review; this guard prevents a new stable identifier from being
// silently absent from its user-facing reference.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(ROOT, path), "utf8");
const required = (document, values, label, codeStyle = true) => {
  const missing = values.filter(
    (value) =>
      !(codeStyle
        ? document.includes(`\`${value}\``)
        : document.toLowerCase().includes(value.toLowerCase())),
  );
  if (missing.length > 0) {
    throw new Error(`${label} documentation is missing: ${missing.join(", ")}`);
  }
};

const reasonsSource = read("packages/core/src/policy/reasons.ts");
const reasonsBlock = reasonsSource.slice(
  reasonsSource.indexOf("export const REASON_CODES"),
  reasonsSource.indexOf("} as const;"),
);
const reasons = [...reasonsBlock.matchAll(/^\s{2}([a-z_]+):/gm)].map((match) => match[1]);
required(read("docs/reason-codes.md"), reasons, "reason-code");

const policyKeys = [
  "version",
  "defaults.unknown_action",
  "defaults.scanner_failure.low_risk",
  "defaults.scanner_failure.high_risk",
  "navigation.mode",
  "navigation.block_private_networks",
  "navigation.max_redirect_hops",
  "navigation.internal_network_ranges",
  "actions.<upload\\|delete\\|purchase\\|message\\|execute_script\\|download\\|authenticate\\|publish\\|change_setting>",
  "secrets.resolution",
  "secrets.restricted_mode",
  "injection.high_confidence",
  "injection.critical",
  "budgets.max_actions",
  "scanners.<id>.patterns",
  "scanners.<id>.enabled",
  "suppressions[]",
  "risk.restricted_at",
  "risk.quarantine_at",
];
required(read("docs/policy-reference.md"), policyKeys, "policy-reference");

const scannerIds = [
  "secret-sensitive",
  "memory-write",
  "encoded-payload",
  "unicode-invisible",
  "hidden-dom",
  "aria",
  "comments",
  "attributes",
  "metadata",
  "url",
  "cross-origin-navigation",
  "local-network-ssrf",
  "secret-exfiltration",
  "file-effect-integrity",
];
required(read("docs/scanners.md"), scannerIds, "scanner-catalog");

const capabilityDocs = [
  read("packages/playwright/README.md"),
  read("docs/stagehand.md"),
  read("packages/cli/README.md"),
].join("\n");
required(
  capabilityDocs,
  ["enforced", "observed_only", "unavailable", "navigation", "fetch", "redirect", "webmcp"],
  "capability",
  false,
);

const rootReadme = read("README.md");
required(
  rootReadme,
  ["OpenAI-compatible", "Ollama", "OpenCode", "doctor --check-provider", "Promptfoo"],
  "external-call",
  false,
);

for (const path of [
  "packages/core/README.md",
  "packages/playwright/README.md",
  "packages/policy/README.md",
  "packages/providers/README.md",
  "packages/scanners/README.md",
  "packages/stagehand/README.md",
  "packages/testing/README.md",
  "packages/vault/README.md",
  "packages/cli/README.md",
]) {
  if (!read(path).includes("api-stability.md")) {
    throw new Error(`${path} must link the v0.1 API stability ledger`);
  }
}

console.log(
  `documentation contract check passed (${reasons.length} reasons, ${scannerIds.length} default scanners)`,
);
