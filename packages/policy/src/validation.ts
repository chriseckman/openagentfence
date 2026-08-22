import { isReasonCode, type ValidatedPolicyRuntimeState } from "@openagentfence/core";
import type { ValidatedPolicyDocument } from "./document.js";

/** Result of validating security-relevant policy combinations. @public */
export interface PolicyValidationReport {
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

/** Validate policy widening, suppressions, and documented static constraints. @public */
export function validatePolicy(document: ValidatedPolicyDocument): PolicyValidationReport {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (document.navigation?.block_private_networks === false)
    warnings.push(
      "navigation.block_private_networks widens a secure default and has no granting effect",
    );
  if (document.actions?.execute_script === "allow")
    warnings.push("actions.execute_script allow cannot widen the capability envelope");
  for (const [index, suppression] of (document.suppressions ?? []).entries()) {
    if (isReasonCode(suppression.rule))
      errors.push(`suppressions[${index}].rule targets final deterministic control`);
    if (suppression.expires !== undefined && Number.isNaN(Date.parse(suppression.expires)))
      errors.push(`suppressions[${index}].expires must be an ISO-compatible timestamp`);
  }
  return Object.freeze({ errors: Object.freeze(errors), warnings: Object.freeze(warnings) });
}

/** Trusted scanner-policy lookup input, intentionally free of finding content. @public */
export interface ScannerPolicyLookup {
  readonly scannerId: string;
  readonly ruleId: string;
  readonly origin?: string;
}
/** Resolved threshold for a firewall-owned deterministic scanner rule. @public */
export interface ScannerThreshold {
  readonly threshold?: number;
  readonly mode?: "warn" | "block";
}

/** Resolve the most-specific configured scanner threshold without mutating policy. @public */
export function resolveScannerThreshold(
  document: ValidatedPolicyDocument,
  input: ScannerPolicyLookup,
): ScannerThreshold | undefined {
  const rule = document.scanners?.[input.scannerId]?.rules?.[input.ruleId];
  if (rule === undefined) return undefined;
  const value = input.origin === undefined ? rule : (rule.origins?.[input.origin] ?? rule);
  return Object.freeze({
    ...(value.threshold !== undefined ? { threshold: value.threshold } : {}),
    ...(value.mode !== undefined ? { mode: value.mode } : {}),
  });
}

/** Trace-safe applied suppression record. @public */
export interface AppliedPolicySuppression {
  readonly rule: string;
  readonly scope: string;
  readonly justification: string;
}

/** Resolve a scanner-only suppression from trusted runtime evidence. @public */
export function resolveScannerSuppression(
  document: ValidatedPolicyDocument,
  runtimeState: ValidatedPolicyRuntimeState,
  input: ScannerPolicyLookup,
): AppliedPolicySuppression | undefined {
  const evidence = runtimeState.scannerEvidence.find(
    (item) =>
      item.scannerId === input.scannerId &&
      item.ruleId === input.ruleId &&
      item.outcome === "finding",
  );
  if (evidence === undefined) return undefined;
  const suppression = document.suppressions?.find(
    (item) => item.rule === input.ruleId && (item.scope === "*" || item.scope === input.origin),
  );
  if (suppression === undefined || isReasonCode(suppression.rule)) return undefined;
  return Object.freeze({
    rule: suppression.rule,
    scope: suppression.scope,
    justification: suppression.justification,
  });
}
