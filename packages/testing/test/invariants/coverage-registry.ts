export const INVARIANT_IDS = Array.from(
  { length: 21 },
  (_, index) => `INV-${String(index + 1).padStart(2, "0")}`,
) as readonly InvariantId[];

export type InvariantId = `INV-${string}`;
export type AttackClassId = `A${number}`;

export interface InvariantCoverageEntry {
  readonly id: InvariantId;
  readonly text: string;
  readonly boundaries: readonly string[];
  readonly deterministicControls: readonly string[];
  readonly corpusCaseIds: readonly string[];
  readonly evidenceFiles: readonly string[];
}

export interface AttackCoverageEntry {
  readonly id: AttackClassId;
  readonly deterministicControls: readonly string[];
  readonly corpusCaseIds: readonly string[];
}

const invariant = (
  id: InvariantId,
  text: string,
  boundaries: readonly string[],
  deterministicControls: readonly string[],
  corpusCaseIds: readonly string[],
  evidenceFiles: readonly string[],
): InvariantCoverageEntry =>
  Object.freeze({ id, text, boundaries, deterministicControls, corpusCaseIds, evidenceFiles });

/** Stable executable OAF-TEST-014 coverage ledger. */
export const INVARIANT_COVERAGE: readonly InvariantCoverageEntry[] = Object.freeze([
  invariant(
    "INV-01",
    "Page content can never grant capabilities.",
    ["TB2", "TB4"],
    ["capability-envelope", "action-guard"],
    ["hidden-dom-display-none-instruction"],
    [
      "packages/testing/test/invariants/INV-01.spec.ts",
      "packages/core/test/contract-boundary.test.ts",
    ],
  ),
  invariant(
    "INV-02",
    "Every attack class has at least one deterministic control.",
    ["all"],
    ["coverage-map"],
    ["ps015-visual-injection-contained"],
    ["packages/testing/test/invariants/INV-02.spec.ts", "packages/testing/test/corpus.test.ts"],
  ),
  invariant(
    "INV-03",
    "Semantic output cannot override a critical deterministic block.",
    ["TB3"],
    ["risk-aggregator", "action-guard"],
    ["byok-false-safe-deterministic-precedence"],
    ["packages/testing/test/invariants/INV-03.spec.ts", "packages/core/test/aggregator.test.ts"],
  ),
  invariant(
    "INV-04",
    "A secret handle cannot resolve for an unapproved sink.",
    ["TB7"],
    ["secret-resolver", "action-guard"],
    ["exfiltration-synthetic-secret"],
    [
      "packages/testing/test/invariants/INV-04.spec.ts",
      "packages/core/test/secret-resolver.test.ts",
    ],
  ),
  invariant(
    "INV-05",
    "Raw secrets never appear in security artifacts.",
    ["TB3", "TB7", "TB9"],
    ["redaction-registry", "secret-handles"],
    ["ps008-handle-form"],
    ["packages/testing/test/invariants/INV-05.spec.ts", "packages/core/test/redact.test.ts"],
  ),
  invariant(
    "INV-06",
    "Cross-origin secret or tainted egress is denied unless explicitly permitted.",
    ["TB6"],
    ["source-sink-check", "egress-inspector"],
    ["exfiltration-cross-origin-tainted-actions"],
    [
      "packages/testing/test/invariants/INV-06.spec.ts",
      "packages/core/test/source-sink-provenance.test.ts",
    ],
  ),
  invariant(
    "INV-07",
    "Persistent web-derived memory remains untrusted.",
    ["TB8"],
    ["memory-write-guard", "memory-read-guard"],
    ["ps009-poisoned-instruction-threat"],
    ["packages/testing/test/invariants/INV-07.spec.ts", "packages/core/test/memory-guard.test.ts"],
  ),
  invariant(
    "INV-08",
    "High-impact actions must pass the Action Guard.",
    ["TB4", "TB5"],
    ["action-guard"],
    ["ps007-high-impact-purchase-missing"],
    ["packages/testing/test/invariants/INV-08.spec.ts", "packages/core/test/runtime.test.ts"],
  ),
  invariant(
    "INV-09",
    "Exhaustion and failure never silently disable protection.",
    ["TB2", "TB3", "TB4"],
    ["required-scanner-fail-closed", "guard-budgets"],
    ["ps014-guard-timeout"],
    [
      "packages/testing/test/invariants/INV-09.spec.ts",
      "packages/core/test/orchestrator-failures.test.ts",
    ],
  ),
  invariant(
    "INV-10",
    "Private-network destinations are denied by default.",
    ["TB6"],
    ["private-network-policy", "network-mutation-guard"],
    ["ps007-ssrf-localhost"],
    ["packages/testing/test/invariants/INV-10.spec.ts", "packages/core/test/destination.test.ts"],
  ),
  invariant(
    "INV-11",
    "Page content cannot approve its own action.",
    ["TB1", "TB4"],
    ["application-approval-handler"],
    ["ps007-high-impact-purchase-missing"],
    ["packages/testing/test/invariants/INV-11.spec.ts", "packages/core/test/approval.test.ts"],
  ),
  invariant(
    "INV-12",
    "The capability envelope only shrinks during a session.",
    ["TB1", "TB4"],
    ["capability-envelope", "risk-state"],
    ["ps007-popup-inherits-restricted"],
    ["packages/testing/test/invariants/INV-12.spec.ts", "packages/core/test/envelope.test.ts"],
  ),
  invariant(
    "INV-13",
    "Provenance survives firewall-visible transformations.",
    ["TB2", "TB4", "TB8"],
    ["provenance-carrier", "taint-floor"],
    ["hidden-dom-display-none-instruction"],
    ["packages/testing/test/invariants/INV-13.spec.ts", "packages/core/test/sanitization.test.ts"],
  ),
  invariant(
    "INV-14",
    "Session risk never resets on navigation.",
    ["TB5"],
    ["risk-state", "post-action-guard"],
    ["ps007-popup-inherits-restricted"],
    ["packages/testing/test/invariants/INV-14.spec.ts", "packages/core/test/post-action.test.ts"],
  ),
  invariant(
    "INV-15",
    "Plugins run with least privilege.",
    ["TB9"],
    ["scoped-plugin-view", "explicit-registration"],
    ["ps015-plugin-least-privilege"],
    [
      "packages/testing/test/invariants/INV-15.spec.ts",
      "packages/core/test/scanner-context.test.ts",
    ],
  ),
  invariant(
    "INV-16",
    "Untrusted inputs, decoders, parsers, and providers are bounded.",
    ["TB1", "TB2", "TB3"],
    ["bounded-decoders", "bounded-schema-validation"],
    ["ps006-encoding-probe-limit"],
    [
      "packages/testing/test/invariants/INV-16.spec.ts",
      "packages/core/test/property/security-properties.test.ts",
      "packages/policy/test/fuzz/policy-properties.test.ts",
      "packages/scanners/test/fuzz/decoder-properties.test.ts",
    ],
  ),
  invariant(
    "INV-17",
    "Every block is explainable with stable reasons and redacted evidence.",
    ["all"],
    ["reason-codes", "trace"],
    ["ps015-visual-injection-contained"],
    [
      "packages/testing/test/invariants/INV-17.spec.ts",
      "packages/core/test/trace-validation.test.ts",
    ],
  ),
  invariant(
    "INV-18",
    "Escape-hatch use is always recorded.",
    ["TB1", "TB5"],
    ["escape-hatch-trace"],
    ["ps015-escape-hatch-recorded"],
    ["packages/testing/test/invariants/INV-18.spec.ts", "packages/core/test/session-trace.test.ts"],
  ),
  invariant(
    "INV-19",
    "Authorization is bound to the exact operation and inspected state.",
    ["TB2", "TB4", "TB5"],
    ["action-intent", "pre-execution-revalidation"],
    ["ps014-mutation-target"],
    ["packages/testing/test/invariants/INV-19.spec.ts", "packages/core/test/action-intent.test.ts"],
  ),
  invariant(
    "INV-20",
    "Probabilistic security components cannot grant authority.",
    ["TB3", "TB4"],
    ["guard-schema", "risk-aggregator"],
    ["ps014-guard-false-safe"],
    [
      "packages/testing/test/invariants/INV-20.spec.ts",
      "packages/core/test/detector-router.test.ts",
    ],
  ),
  invariant(
    "INV-21",
    "Network mutations do not inherit authorization implicitly.",
    ["TB2", "TB6"],
    ["network-mutation-guard", "evidence-only-correlation"],
    ["ps014-network-script-fetch-enforced"],
    [
      "packages/testing/test/invariants/INV-21.spec.ts",
      "packages/core/test/network-mutation.test.ts",
    ],
  ),
]);

const attack = (
  id: AttackClassId,
  deterministicControls: readonly string[],
  corpusCaseIds: readonly string[],
): AttackCoverageEntry => Object.freeze({ id, deterministicControls, corpusCaseIds });

/** Removal-sensitive A1-A20 map. Scanner IDs must exist in `defaultScanners()`. */
export const ATTACK_COVERAGE: readonly AttackCoverageEntry[] = Object.freeze([
  attack(
    "A1",
    ["hidden-dom", "aria", "capability-envelope"],
    ["hidden-dom-display-none-instruction"],
  ),
  attack("A2", ["action-guard", "capability-envelope"], ["ps015-visual-injection-contained"]),
  attack("A3", ["hidden-dom", "aria"], ["aria-accessibility-only-instruction"]),
  attack("A4", ["encoded-payload", "unicode-invisible"], ["encoding-base64-instruction"]),
  attack(
    "A5",
    ["secret-exfiltration", "egress-inspector"],
    ["exfiltration-cross-origin-tainted-actions"],
  ),
  attack("A6", ["secret-sensitive", "secret-resolver"], ["exfiltration-synthetic-secret"]),
  attack("A7", ["capability-envelope", "action-guard"], ["ps007-high-impact-purchase-missing"]),
  attack("A8", ["action-guard", "secret-exfiltration"], ["ps008-handle-form"]),
  attack(
    "A9",
    ["action-guard", "application-approval-handler"],
    ["ps007-high-impact-purchase-missing"],
  ),
  attack("A10", ["local-network-ssrf", "network-mutation-guard"], ["ps007-ssrf-localhost"]),
  attack("A11", ["file-effect-integrity", "action-guard"], ["ps008-handle-upload-path"]),
  attack("A12", ["memory-write", "memory-read-guard"], ["ps009-poisoned-instruction-threat"]),
  attack("A13", ["url", "origin-policy"], ["ps007-redirect-blocked-origin"]),
  attack(
    "A14",
    ["provenance-carrier", "taint-floor"],
    ["exfiltration-cross-origin-tainted-actions"],
  ),
  attack("A15", ["guard-budgets", "session-budgets"], ["ps007-budget-navigation-over-limit"]),
  attack("A16", ["popup-budget", "post-action-guard"], ["ps015-popup-post-effect-contained"]),
  attack("A17", ["url", "metadata"], ["ps006-encoding-title-attribute"]),
  attack("A18", ["action-intent", "pre-execution-revalidation"], ["ps014-mutation-target"]),
  attack("A19", ["guard-schema", "risk-aggregator"], ["ps014-guard-malformed"]),
  attack(
    "A20",
    ["network-mutation-guard", "evidence-only-correlation"],
    ["ps014-network-script-fetch-enforced"],
  ),
]);

export const SCANNER_CONTROL_IDS = new Set([
  "hidden-dom",
  "aria",
  "encoded-payload",
  "unicode-invisible",
  "secret-exfiltration",
  "secret-sensitive",
  "local-network-ssrf",
  "file-effect-integrity",
  "memory-write",
  "url",
  "metadata",
]);

export const DETERMINISTIC_CONTROL_IDS = new Set([
  ...SCANNER_CONTROL_IDS,
  "action-guard",
  "application-approval-handler",
  "bounded-decoders",
  "bounded-schema-validation",
  "capability-envelope",
  "coverage-map",
  "egress-inspector",
  "evidence-only-correlation",
  "explicit-registration",
  "guard-budgets",
  "guard-schema",
  "memory-read-guard",
  "network-mutation-guard",
  "origin-policy",
  "popup-budget",
  "post-action-guard",
  "pre-execution-revalidation",
  "private-network-policy",
  "provenance-carrier",
  "reason-codes",
  "redaction-registry",
  "required-scanner-fail-closed",
  "risk-aggregator",
  "risk-state",
  "scoped-plugin-view",
  "secret-handles",
  "secret-resolver",
  "session-budgets",
  "source-sink-check",
  "taint-floor",
  "trace",
  "escape-hatch-trace",
  "action-intent",
]);

interface CoverageCorpusCase {
  readonly id: string;
  readonly attackClasses: readonly string[];
  readonly expected: { readonly control?: string };
}

/** Pure removal-regression oracle for A1-A20 deterministic coverage. */
export function attackCoverageErrors(
  entries: readonly AttackCoverageEntry[],
  cases: readonly CoverageCorpusCase[],
  scannerIds: ReadonlySet<string>,
): readonly string[] {
  const errors: string[] = [];
  const byId = new Map(cases.map((item) => [item.id, item]));
  const expectedIds = Array.from({ length: 20 }, (_, index) => `A${index + 1}`);
  if (entries.map((entry) => entry.id).join(",") !== expectedIds.join(",")) {
    errors.push("attack-class-set");
  }
  for (const entry of entries) {
    if (entry.deterministicControls.length === 0) errors.push(`${entry.id}:control-missing`);
    for (const control of entry.deterministicControls) {
      if (!DETERMINISTIC_CONTROL_IDS.has(control)) errors.push(`${entry.id}:control-unknown`);
      if (SCANNER_CONTROL_IDS.has(control) && !scannerIds.has(control)) {
        errors.push(`${entry.id}:scanner-missing`);
      }
    }
    if (entry.corpusCaseIds.length === 0) errors.push(`${entry.id}:case-missing`);
    for (const caseId of entry.corpusCaseIds) {
      const item = byId.get(caseId);
      if (item === undefined) {
        errors.push(`${entry.id}:case-absent`);
      } else {
        if (!item.attackClasses.includes(entry.id)) errors.push(`${entry.id}:class-unlinked`);
        if (item.expected.control !== "deterministic" && item.expected.control !== "approval") {
          errors.push(`${entry.id}:case-not-deterministic`);
        }
      }
    }
  }
  return Object.freeze(errors);
}

export const GUARANTEE_COVERAGE = Object.freeze([
  {
    id: "classifier-miss",
    invariant: "INV-01",
    corpusCaseId: "byok-false-safe-deterministic-precedence",
  },
  { id: "obedient-agent", invariant: "INV-08", corpusCaseId: "ps015-visual-injection-contained" },
  { id: "guard-compromise", invariant: "INV-20", corpusCaseId: "ps014-guard-malformed" },
  { id: "secret-at-sink", invariant: "INV-04", corpusCaseId: "ps008-handle-form" },
  { id: "external-private-navigation", invariant: "INV-10", corpusCaseId: "ps007-ssrf-localhost" },
  { id: "authorized-state-mutates", invariant: "INV-19", corpusCaseId: "ps014-mutation-target" },
  {
    id: "unexpected-network",
    invariant: "INV-21",
    corpusCaseId: "ps014-network-script-fetch-enforced",
  },
  { id: "poisoned-memory", invariant: "INV-07", corpusCaseId: "ps009-poisoned-instruction-threat" },
  { id: "inspection-exhaustion", invariant: "INV-09", corpusCaseId: "ps014-guard-timeout" },
  { id: "adapter-hook-gap", invariant: "INV-21", corpusCaseId: "ps014-network-webmcp-unavailable" },
]);
