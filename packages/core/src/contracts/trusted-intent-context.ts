import { ACTION_TYPES } from "../action/canonical-action.js";
import type { CanonicalAction } from "../action/canonical-action.js";
import type { DataProvenance, TrustLevel } from "./provenance.js";
import type { RiskState } from "./risk-state.js";

/**
 * Deterministic, allowlisted trusted context for (future) intent criticism
 * (OAF-CORE-016, INV-20). It contains only firewall-owned facts: the trusted
 * task, the canonical action/destination, envelope facts, data
 * classifications, safe provenance labels, the current risk state, and
 * summaries of prior trusted actions. It can never absorb raw page/tool/memory
 * content, screenshots, manifests, decoded payloads, raw secrets, or arbitrary
 * metadata. A sanitized string does not become trusted merely because the
 * firewall transformed it.
 */
export interface TrustedIntentContext {
  readonly task: string;
  readonly action: CanonicalAction;
  readonly envelopeFacts: Readonly<Record<string, boolean>>;
  readonly dataClassifications: readonly string[];
  readonly riskState: RiskState;
  readonly provenance: DataProvenance;
  readonly priorActions: readonly string[];
}

const TRUSTED_INTENT: unique symbol = Symbol("openagentfence.intent.trusted");

export type TrustedIntent = TrustedIntentContext & {
  readonly [TRUSTED_INTENT]: true;
};

export function isTrustedIntent(value: unknown): value is TrustedIntent {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.isFrozen(value) &&
    Object.getOwnPropertySymbols(value).includes(TRUSTED_INTENT)
  );
}

const SAFE_TRUST: readonly TrustLevel[] = ["user", "application"];
const RISK_STATES: readonly string[] = ["NORMAL", "RESTRICTED", "READ_ONLY", "QUARANTINED"];

const MAX_TASK_LENGTH = 4096;
const MAX_FACT_KEYS = 50;
const MAX_FACT_KEY_LENGTH = 64;
const MAX_CLASSIFICATIONS = 20;
const MAX_CLASSIFICATION_LENGTH = 64;
const MAX_PRIOR_ACTIONS = 20;
const MAX_PRIOR_ACTION_LENGTH = 256;

const CONTEXT_KEYS: readonly string[] = [
  "task",
  "action",
  "envelopeFacts",
  "dataClassifications",
  "riskState",
  "provenance",
  "priorActions",
];

export type TrustedIntentValidationResult =
  | { readonly ok: true; readonly value: TrustedIntent }
  | { readonly ok: false; readonly errors: readonly string[] };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  errors: string[],
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      errors.push(`unknown key "${key}"`);
    }
  }
}

function validateSafeProvenance(value: unknown, errors: string[]): DataProvenance | null {
  if (!isRecord(value)) {
    errors.push("provenance must be an object");
    return null;
  }
  rejectUnknownKeys(
    value,
    ["trust", "origin", "frameOrigin", "pageId", "elementId", "timestamp"],
    errors,
  );
  const trust = value["trust"];
  if (typeof trust !== "string" || !SAFE_TRUST.includes(trust as TrustLevel)) {
    errors.push("provenance.trust must be user or application (safe provenance only)");
    return null;
  }
  const out: Record<string, unknown> = { trust };
  for (const key of ["origin", "frameOrigin", "pageId", "elementId", "timestamp"]) {
    const field = value[key];
    if (field !== undefined) {
      if (typeof field !== "string") {
        errors.push(`provenance.${key} must be a string`);
      } else {
        out[key] = field;
      }
    }
  }
  return out as unknown as DataProvenance;
}

function validateAction(value: unknown, errors: string[]): CanonicalAction | null {
  if (!isRecord(value)) {
    errors.push("action must be an object");
    return null;
  }
  const type = value["type"];
  if (typeof type !== "string" || !(ACTION_TYPES as readonly string[]).includes(type)) {
    errors.push("action.type must be a known action type");
    return null;
  }
  return value as unknown as CanonicalAction;
}

/** Strict, bounded runtime validation of the trusted intent context (INV-16/20). */
export function validateTrustedIntentContext(input: unknown): TrustedIntentValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: ["trusted intent context must be an object"] };
  }
  rejectUnknownKeys(input, CONTEXT_KEYS, errors);

  const task = input["task"];
  if (typeof task !== "string" || task.trim().length === 0 || task.length > MAX_TASK_LENGTH) {
    errors.push(`task must be a non-empty string of at most ${MAX_TASK_LENGTH} characters`);
  }

  const action = validateAction(input["action"], errors);

  let envelopeFacts: Readonly<Record<string, boolean>> = {};
  const facts = input["envelopeFacts"];
  if (!isRecord(facts)) {
    errors.push("envelopeFacts must be an object");
  } else {
    rejectUnknownKeys(facts, Object.keys(facts), errors);
    const keys = Object.keys(facts);
    if (keys.length > MAX_FACT_KEYS) {
      errors.push(`envelopeFacts must have at most ${MAX_FACT_KEYS} keys`);
    }
    for (const key of keys) {
      if (key.length === 0 || key.length > MAX_FACT_KEY_LENGTH) {
        errors.push("envelopeFacts keys must be 1-64 characters");
      }
      if (typeof facts[key] !== "boolean") {
        errors.push(`envelopeFacts.${key} must be a boolean`);
      }
    }
    envelopeFacts = Object.freeze({ ...facts }) as Readonly<Record<string, boolean>>;
  }

  let dataClassifications: readonly string[] = [];
  const classifications = input["dataClassifications"];
  if (!Array.isArray(classifications)) {
    errors.push("dataClassifications must be an array");
  } else {
    const items: readonly unknown[] = classifications;
    if (items.length > MAX_CLASSIFICATIONS) {
      errors.push(`dataClassifications must have at most ${MAX_CLASSIFICATIONS} items`);
    }
    for (const item of items) {
      if (
        typeof item !== "string" ||
        item.length === 0 ||
        item.length > MAX_CLASSIFICATION_LENGTH
      ) {
        errors.push("dataClassifications items must be non-empty strings");
      }
    }
    dataClassifications = Object.freeze([...items] as string[]);
  }

  const riskState = input["riskState"];
  if (typeof riskState !== "string" || !RISK_STATES.includes(riskState)) {
    errors.push("riskState must be a known risk state");
  }

  const provenance = validateSafeProvenance(input["provenance"], errors);

  let priorActions: readonly string[] = [];
  const priors = input["priorActions"];
  if (!Array.isArray(priors)) {
    errors.push("priorActions must be an array");
  } else {
    const items: readonly unknown[] = priors;
    if (items.length > MAX_PRIOR_ACTIONS) {
      errors.push(`priorActions must have at most ${MAX_PRIOR_ACTIONS} items`);
    }
    for (const item of items) {
      if (typeof item !== "string" || item.length > MAX_PRIOR_ACTION_LENGTH) {
        errors.push(
          `priorActions items must be strings of at most ${MAX_PRIOR_ACTION_LENGTH} characters`,
        );
      }
    }
    priorActions = Object.freeze([...items] as string[]);
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  const value: TrustedIntentContext = {
    task: task as string,
    action: action as CanonicalAction,
    envelopeFacts,
    dataClassifications,
    riskState: riskState as RiskState,
    provenance: provenance as DataProvenance,
    priorActions,
  };
  const branded = Object.defineProperty(value, TRUSTED_INTENT, {
    value: true as const,
    enumerable: false,
  }) as TrustedIntent;
  return { ok: true, value: deepFreeze(branded) };
}

/**
 * Build a trusted intent context from the documented allowlist. Throws a
 * `TypeError` on any violation (unsafe provenance, unknown/oversized fields).
 */
export function buildTrustedIntentContext(input: TrustedIntentContext): TrustedIntent {
  const result = validateTrustedIntentContext(input);
  if (!result.ok) {
    throw new TypeError(`invalid trusted intent context: ${result.errors.join("; ")}`);
  }
  return result.value;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const key of Object.getOwnPropertyNames(value)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}
