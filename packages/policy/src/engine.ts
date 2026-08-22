import { createHash } from "node:crypto";
import {
  REASON_CODES,
  DEFAULT_DESTINATION_RULES,
  originOf,
  sameSite,
  isReasonCode,
  type PolicyDecision,
  type PolicyEngine,
  type PolicyEvaluationInput,
} from "@openagentfence/core";
import type { PolicyDocument, ValidatedPolicyDocument } from "./document.js";

const ACTION_POLICY_KEYS: Readonly<Record<string, keyof NonNullable<PolicyDocument["actions"]>>> = {
  UPLOAD: "upload",
  DELETE: "delete",
  PURCHASE: "purchase",
  MESSAGE: "message",
  EXECUTE_SCRIPT: "execute_script",
  DOWNLOAD: "download",
  AUTHENTICATE: "authenticate",
  PUBLISH: "publish",
  CHANGE_SETTING: "change_setting",
};

/** Create the pure, synchronous document-driven policy engine (ADR-0008). @public */
export function createPolicyEngine(document: ValidatedPolicyDocument): PolicyEngine {
  const policyHash = hashPolicyDocument(document);
  const destinationRules = Object.freeze({
    blockPrivateNetworks: document.navigation?.block_private_networks === true,
    internalNetworkRanges: Object.freeze([...(document.navigation?.internal_network_ranges ?? [])]),
    maxRedirectHops:
      document.navigation?.max_redirect_hops ?? DEFAULT_DESTINATION_RULES.maxRedirectHops,
  });
  return Object.freeze({
    policyHash,
    destinationRules,
    secretResolution: Object.freeze({
      restrictedMode: document.secrets?.restricted_mode ?? "keep_approved_sinks",
    }),
    evaluate(input: PolicyEvaluationInput): PolicyDecision {
      const envelope = input.envelope.evaluate(input.action);
      if (!envelope.allowed)
        return decision("BLOCK", envelope.reasons, ["capability-envelope"], policyHash);
      if (input.riskState === "QUARANTINED")
        return decision(
          "BLOCK",
          [REASON_CODES.session_restricted],
          ["risk.quarantined"],
          policyHash,
        );
      const budget = evaluateBudgets(document, input, policyHash);
      if (budget !== undefined) return budget;
      const scanner = evaluateScannerFailure(document, input, policyHash);
      if (scanner !== undefined) return scanner;
      const injection = evaluateInjection(document, input, policyHash);
      if (injection !== undefined) return injection;
      const navigation = evaluateNavigation(document, input, policyHash);
      if (navigation !== undefined) return navigation;
      const action = evaluateAction(document, input, policyHash);
      if (action !== undefined) return action;
      return decision("ALLOW", [], [], policyHash, undefined, appliedSuppressions(document, input));
    },
  });
}

/** Canonical SHA-256 identity, independent of source key order and branding. @public */
export function hashPolicyDocument(document: ValidatedPolicyDocument): string {
  return createHash("sha256").update(canonicalJson(document), "utf8").digest("hex");
}

function evaluateBudgets(
  document: ValidatedPolicyDocument,
  input: PolicyEvaluationInput,
  policyHash: string,
): PolicyDecision | undefined {
  const budgets = document.budgets;
  if (budgets === undefined) return undefined;
  const usage = input.runtimeState.budget;
  const exceeded =
    (budgets.max_actions !== undefined && usage.actionsUsed >= budgets.max_actions) ||
    (budgets.max_navigations !== undefined && usage.navigationsUsed >= budgets.max_navigations) ||
    (budgets.max_duration_ms !== undefined && usage.elapsedMs >= budgets.max_duration_ms);
  if (!exceeded) return undefined;
  return decision(
    budgets.on_exceeded === "restricted_mode" ? "RESTRICT" : "BLOCK",
    [REASON_CODES.budget_exceeded],
    ["budgets.on_exceeded"],
    policyHash,
  );
}

function evaluateScannerFailure(
  document: ValidatedPolicyDocument,
  input: PolicyEvaluationInput,
  policyHash: string,
): PolicyDecision | undefined {
  const failure = input.runtimeState.scannerEvidence.find(
    (evidence) => evidence.outcome === "failure",
  );
  if (failure === undefined) return undefined;
  const configured =
    failure.severity === "low"
      ? document.defaults?.scanner_failure?.low_risk
      : document.defaults?.scanner_failure?.high_risk;
  if (configured === "warn")
    return decision(
      "WARN",
      [REASON_CODES.scanner_unavailable],
      ["defaults.scanner_failure.low_risk"],
      policyHash,
    );
  return decision(
    "BLOCK",
    [REASON_CODES.scanner_unavailable],
    ["defaults.scanner_failure"],
    policyHash,
  );
}

function evaluateInjection(
  document: ValidatedPolicyDocument,
  input: PolicyEvaluationInput,
  policyHash: string,
): PolicyDecision | undefined {
  const evidence = input.runtimeState.scannerEvidence.find(
    (item) => item.outcome === "finding" && item.scannerId === "injection",
  );
  if (evidence === undefined) return undefined;
  if (evidence.severity === "critical" && document.injection?.critical !== undefined)
    return decision(
      "BLOCK",
      [REASON_CODES.session_contains_high_confidence_prompt_injection],
      ["injection.critical"],
      policyHash,
    );
  if (evidence.severity === "high" && document.injection?.high_confidence === "block")
    return decision(
      "BLOCK",
      [REASON_CODES.session_contains_high_confidence_prompt_injection],
      ["injection.high_confidence"],
      policyHash,
    );
  if (evidence.severity === "high" && document.injection?.high_confidence === "restricted_mode")
    return decision(
      "RESTRICT",
      [REASON_CODES.session_contains_high_confidence_prompt_injection],
      ["injection.high_confidence"],
      policyHash,
    );
  return undefined;
}

function evaluateNavigation(
  document: ValidatedPolicyDocument,
  input: PolicyEvaluationInput,
  policyHash: string,
): PolicyDecision | undefined {
  if (input.action.type !== "NAVIGATE") return undefined;
  const mode = document.navigation?.mode;
  if (mode === undefined) return undefined;
  if (mode === "none")
    return decision(
      "BLOCK",
      [REASON_CODES.destination_not_allowed],
      ["navigation.mode"],
      policyHash,
    );
  const destination = input.action.destination;
  if (destination === undefined)
    return decision(
      "BLOCK",
      [REASON_CODES.destination_not_allowed],
      ["navigation.destination"],
      policyHash,
    );
  const origin = input.action.target?.origin;
  if (mode === "same-origin" && originOf(destination) !== origin)
    return decision(
      "BLOCK",
      [REASON_CODES.destination_not_allowed],
      ["navigation.mode"],
      policyHash,
    );
  if (mode === "same-site" && !sameSite(destination, origin ?? ""))
    return decision(
      "BLOCK",
      [REASON_CODES.destination_not_allowed],
      ["navigation.mode"],
      policyHash,
    );
  return undefined;
}

function evaluateAction(
  document: ValidatedPolicyDocument,
  input: PolicyEvaluationInput,
  policyHash: string,
): PolicyDecision | undefined {
  if (input.action.type === "UNKNOWN" && document.defaults?.unknown_action === "block")
    return decision(
      "BLOCK",
      [REASON_CODES.unknown_action],
      ["defaults.unknown_action"],
      policyHash,
    );
  const key = ACTION_POLICY_KEYS[input.action.type];
  const disposition = key === undefined ? undefined : document.actions?.[key];
  if (disposition === "deny")
    return decision("BLOCK", [REASON_CODES.capability_denied], [`actions.${key}`], policyHash);
  if (disposition === "approval")
    return decision(
      "REQUIRE_APPROVAL",
      [REASON_CODES.approval_required],
      [`actions.${key}`],
      policyHash,
      true,
    );
  return undefined;
}

function decision(
  verdict: PolicyDecision["verdict"],
  reasons: readonly PolicyDecision["reasons"][number][],
  matchedRules: readonly string[],
  policyHash: string,
  requiredApproval?: boolean,
  appliedSuppressions?: readonly {
    readonly rule: string;
    readonly scope: string;
    readonly justification: string;
  }[],
): PolicyDecision {
  return {
    verdict,
    reasons,
    matchedRules,
    policyHash,
    ...(requiredApproval === true ? { requiredApproval } : {}),
    ...(appliedSuppressions !== undefined && appliedSuppressions.length > 0
      ? { appliedSuppressions }
      : {}),
  };
}

function appliedSuppressions(
  document: ValidatedPolicyDocument,
  input: PolicyEvaluationInput,
): readonly { readonly rule: string; readonly scope: string; readonly justification: string }[] {
  return input.runtimeState.scannerEvidence
    .filter((evidence) => evidence.outcome === "finding")
    .flatMap((evidence) => {
      const match = document.suppressions?.find(
        (suppression) =>
          suppression.rule === evidence.ruleId &&
          (suppression.scope === "*" || suppression.scope === evidence.origin),
      );
      return match === undefined || isReasonCode(match.rule)
        ? []
        : [{ rule: match.rule, scope: match.scope, justification: match.justification }];
    });
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}
