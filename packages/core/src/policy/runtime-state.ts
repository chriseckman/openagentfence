/** Trusted, bounded evidence summary available to deterministic policy. */
export interface PolicyScannerEvidence {
  readonly scannerId: string;
  readonly ruleId: string;
  readonly origin?: string;
  readonly kind: "deterministic";
  readonly outcome: "finding" | "failure";
  readonly severity: "low" | "high" | "critical";
}

/**
 * Immutable firewall-owned facts for policy evaluation (ADR-0013). This is a
 * summary, not scanner output: it deliberately excludes page content, finding
 * evidence, semantic model results, providers, callbacks, and secret values.
 */
export interface PolicyRuntimeState {
  readonly budget: {
    readonly actionsUsed: number;
    readonly navigationsUsed: number;
    readonly elapsedMs: number;
  };
  readonly scannerEvidence: readonly PolicyScannerEvidence[];
}

const VALIDATED_POLICY_RUNTIME_STATE: unique symbol = Symbol(
  "openagentfence.policyRuntimeState.validated",
);

/** A runtime state created by the firewall after strict boundary validation. */
export type ValidatedPolicyRuntimeState = PolicyRuntimeState & {
  readonly [VALIDATED_POLICY_RUNTIME_STATE]: true;
};

const MAX_SCANNER_EVIDENCE = 256;
const MAX_IDENTIFIER_LENGTH = 128;

/** Validate and deeply freeze firewall-owned runtime policy facts. */
export function createPolicyRuntimeState(input: unknown): ValidatedPolicyRuntimeState {
  if (!isRecord(input)) throw new TypeError("policy runtime state must be an object");
  rejectUnknown(input, ["budget", "scannerEvidence"], "policy runtime state");
  const budget = input["budget"];
  if (!isRecord(budget)) throw new TypeError("policy runtime state.budget must be an object");
  rejectUnknown(
    budget,
    ["actionsUsed", "navigationsUsed", "elapsedMs"],
    "policy runtime state.budget",
  );
  const actionsUsed = nonNegativeNumber(
    budget["actionsUsed"],
    "policy runtime state.budget.actionsUsed",
  );
  const navigationsUsed = nonNegativeNumber(
    budget["navigationsUsed"],
    "policy runtime state.budget.navigationsUsed",
  );
  const elapsedMs = nonNegativeNumber(budget["elapsedMs"], "policy runtime state.budget.elapsedMs");
  const rawEvidence = input["scannerEvidence"];
  if (!Array.isArray(rawEvidence) || rawEvidence.length > MAX_SCANNER_EVIDENCE) {
    throw new TypeError("policy runtime state.scannerEvidence must be a bounded array");
  }
  const scannerEvidence = rawEvidence.map((entry, index) =>
    Object.freeze(validateEvidence(entry, index)),
  );
  const state: PolicyRuntimeState = {
    budget: { actionsUsed, navigationsUsed, elapsedMs },
    scannerEvidence,
  };
  Object.defineProperty(state, VALIDATED_POLICY_RUNTIME_STATE, {
    value: true as const,
    enumerable: false,
  });
  Object.freeze(state.budget);
  Object.freeze(state.scannerEvidence);
  return Object.freeze(state) as ValidatedPolicyRuntimeState;
}

/** Runtime guard for the policy-runtime trust boundary. */
export function isValidatedPolicyRuntimeState(
  value: unknown,
): value is ValidatedPolicyRuntimeState {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.isFrozen(value) &&
    Object.getOwnPropertySymbols(value).includes(VALIDATED_POLICY_RUNTIME_STATE)
  );
}

/** Empty trusted state for sessions that have not yet accumulated runtime facts. */
export const emptyPolicyRuntimeState = createPolicyRuntimeState({
  budget: { actionsUsed: 0, navigationsUsed: 0, elapsedMs: 0 },
  scannerEvidence: [],
});

function validateEvidence(input: unknown, index: number): PolicyScannerEvidence {
  const path = `policy runtime state.scannerEvidence[${index}]`;
  if (!isRecord(input)) throw new TypeError(`${path} must be an object`);
  rejectUnknown(input, ["scannerId", "ruleId", "origin", "kind", "outcome", "severity"], path);
  const scannerId = identifier(input["scannerId"], `${path}.scannerId`);
  const ruleId = identifier(input["ruleId"], `${path}.ruleId`);
  const origin = input["origin"];
  if (
    origin !== undefined &&
    (typeof origin !== "string" || origin.length > MAX_IDENTIFIER_LENGTH)
  ) {
    throw new TypeError(`${path}.origin must be a bounded string`);
  }
  if (input["kind"] !== "deterministic") throw new TypeError(`${path}.kind must be deterministic`);
  if (input["outcome"] !== "finding" && input["outcome"] !== "failure")
    throw new TypeError(`${path}.outcome is invalid`);
  if (
    input["severity"] !== "low" &&
    input["severity"] !== "high" &&
    input["severity"] !== "critical"
  )
    throw new TypeError(`${path}.severity is invalid`);
  return {
    scannerId,
    ruleId,
    ...(origin !== undefined ? { origin } : {}),
    kind: "deterministic",
    outcome: input["outcome"],
    severity: input["severity"],
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  return Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null;
}

function rejectUnknown(
  input: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
): void {
  for (const key of Object.keys(input))
    if (!allowed.includes(key)) throw new TypeError(`${path}.${key} is not allowed`);
}

function nonNegativeNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0)
    throw new TypeError(`${path} must be a non-negative number`);
  return value;
}

function identifier(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH)
    throw new TypeError(`${path} must be a bounded non-empty string`);
  return value;
}
