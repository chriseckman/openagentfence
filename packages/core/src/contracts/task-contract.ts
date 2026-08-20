import type { SecretHandleKind } from "../secrets/handle-codec.js";
import { originOf } from "../action/url.js";

export type NavigationMode = "same-site" | "same-origin" | "allowlist" | "none";

export interface TaskCapabilities {
  readonly navigation?: NavigationMode;
  readonly downloads?: boolean;
  readonly uploads?: boolean;
  readonly purchases?: boolean;
  readonly messaging?: boolean;
  readonly destructiveActions?: boolean;
  readonly credentials?: boolean;
  readonly executeScript?: boolean;
  readonly privateNetwork?: boolean;
  readonly externalCommunication?: boolean;
}

/** Sink-binding declaration carried in the trusted task contract (ADR-0005). */
export interface SecretBindingDecl {
  readonly name: string;
  readonly kind: SecretHandleKind;
  readonly origins: readonly string[];
  readonly fieldTypes: readonly string[];
  readonly selector?: string;
  readonly formAction?: string;
}

export interface OriginAllowances {
  readonly allow?: readonly string[];
  readonly block?: readonly string[];
}

export interface BudgetConfig {
  readonly maxActions?: number;
  readonly maxDurationMs?: number;
  readonly maxNavigations?: number;
  readonly maxRedirectHops?: number;
  readonly maxGuardCalls?: number;
  readonly maxGuardTokens?: number;
  readonly maxDownloads?: number;
  readonly maxDownloadBytes?: number;
  readonly maxUploadBytes?: number;
  readonly maxTabs?: number;
}

export interface ApprovalConfig {
  readonly required?: boolean;
  readonly timeoutMs?: number;
}

/**
 * Trusted statement of intent from the application (ARCHITECTURE §4). Validated
 * at `session.start()` and immutable thereafter. Page content can never modify
 * it; it is the only source of capability besides the `PolicyEngine`.
 */
export interface TaskContract {
  readonly task: string;
  readonly capabilities?: TaskCapabilities;
  readonly secrets?: readonly SecretBindingDecl[];
  readonly origins?: OriginAllowances;
  readonly budgets?: BudgetConfig;
  readonly approval?: ApprovalConfig;
}

const VALIDATED_TASK_CONTRACT: unique symbol = Symbol("openagentfence.taskContract.validated");

/**
 * A `TaskContract` that has passed `validateTaskContract`. Produced only by the
 * validator; the `CapabilityEnvelope` compiler accepts only this form, so raw,
 * page-supplied, or structurally similar objects cannot reach it
 * (INV-01, INV-12, TB1).
 */
export type ValidatedTaskContract = TaskContract & {
  readonly [VALIDATED_TASK_CONTRACT]: true;
};

/** Runtime guard for the validated-contract brand (JS callers can bypass types). */
export function isValidatedTaskContract(value: unknown): value is ValidatedTaskContract {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.isFrozen(value) &&
    Object.getOwnPropertySymbols(value).includes(VALIDATED_TASK_CONTRACT)
  );
}

const NAVIGATION_MODES: readonly string[] = ["same-site", "same-origin", "allowlist", "none"];
const CAPABILITY_KEYS: readonly string[] = [
  "navigation",
  "downloads",
  "uploads",
  "purchases",
  "messaging",
  "destructiveActions",
  "credentials",
  "executeScript",
  "privateNetwork",
  "externalCommunication",
];
const BUDGET_KEYS: readonly string[] = [
  "maxActions",
  "maxDurationMs",
  "maxNavigations",
  "maxRedirectHops",
  "maxGuardCalls",
  "maxGuardTokens",
  "maxDownloads",
  "maxDownloadBytes",
  "maxUploadBytes",
  "maxTabs",
];
const ORIGIN_KEYS: readonly string[] = ["allow", "block"];
const APPROVAL_KEYS: readonly string[] = ["required", "timeoutMs"];
const CONTRACT_KEYS: readonly string[] = [
  "task",
  "capabilities",
  "secrets",
  "origins",
  "budgets",
  "approval",
];

export type ValidationResult =
  | { readonly ok: true; readonly value: ValidatedTaskContract }
  | { readonly ok: false; readonly errors: readonly string[] };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
  errors: string[],
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      errors.push(`${path}: unknown key "${key}"`);
    }
  }
}

/**
 * Strict runtime validation at the trust boundary (TB1). Unknown keys are
 * rejected and every field is type-checked. Returns a deeply frozen contract
 * on success.
 */
export function validateTaskContract(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: ["task contract must be an object"] };
  }
  rejectUnknownKeys(input, CONTRACT_KEYS, "taskContract", errors);

  const task = input["task"];
  if (typeof task !== "string" || task.trim().length === 0) {
    errors.push("taskContract.task must be a non-empty string");
  }

  let capabilities: TaskCapabilities | undefined;
  const capsInput = input["capabilities"];
  if (capsInput !== undefined) {
    if (!isRecord(capsInput)) {
      errors.push("taskContract.capabilities must be an object");
    } else {
      rejectUnknownKeys(capsInput, CAPABILITY_KEYS, "taskContract.capabilities", errors);
      const built: Record<string, unknown> = {};
      const navigation = capsInput["navigation"];
      if (navigation !== undefined) {
        if (typeof navigation !== "string" || !NAVIGATION_MODES.includes(navigation)) {
          errors.push(
            `taskContract.capabilities.navigation must be one of ${NAVIGATION_MODES.join(", ")}`,
          );
        } else {
          built["navigation"] = navigation;
        }
      }
      for (const key of CAPABILITY_KEYS.filter((k) => k !== "navigation")) {
        const value = capsInput[key];
        if (value !== undefined) {
          if (typeof value !== "boolean") {
            errors.push(`taskContract.capabilities.${key} must be a boolean`);
          } else {
            built[key] = value;
          }
        }
      }
      if (Object.keys(built).length > 0) {
        capabilities = built as TaskCapabilities;
      }
    }
  }

  let secrets: SecretBindingDecl[] | undefined;
  const secretsInput = input["secrets"];
  if (secretsInput !== undefined) {
    if (!Array.isArray(secretsInput)) {
      errors.push("taskContract.secrets must be an array");
    } else {
      secrets = [];
      if (secretsInput.length > 64)
        errors.push("taskContract.secrets must contain at most 64 bindings");
      for (let i = 0; i < Math.min(secretsInput.length, 65); i += 1) {
        const item = secretsInput[i];
        if (!isRecord(item)) {
          errors.push(`taskContract.secrets[${i}] must be an object`);
          continue;
        }
        rejectUnknownKeys(
          item,
          ["name", "kind", "origins", "fieldTypes", "selector", "formAction"],
          `taskContract.secrets[${i}]`,
          errors,
        );
        const name = item["name"];
        const kind = item["kind"];
        const origins = item["origins"];
        const fieldTypes = item["fieldTypes"];
        const selector = item["selector"];
        const formAction = item["formAction"];
        if (typeof name !== "string" || !/^[A-Za-z0-9._-]{1,96}$/.test(name)) {
          errors.push(`taskContract.secrets[${i}].name must be a bounded handle name`);
        }
        if (kind !== "SECRET" && kind !== "PII" && kind !== "CREDENTIAL") {
          errors.push(`taskContract.secrets[${i}].kind must be SECRET, PII, or CREDENTIAL`);
        }
        if (
          !Array.isArray(origins) ||
          origins.length === 0 ||
          origins.length > 32 ||
          origins.some((o) => typeof o !== "string" || o.length > 2048 || originOf(o) !== o)
        ) {
          errors.push(`taskContract.secrets[${i}].origins must contain 1-32 canonical origins`);
        }
        if (
          !Array.isArray(fieldTypes) ||
          fieldTypes.length === 0 ||
          fieldTypes.length > 32 ||
          fieldTypes.some((f) => typeof f !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/.test(f))
        ) {
          errors.push(
            `taskContract.secrets[${i}].fieldTypes must contain 1-32 bounded field types`,
          );
        }
        if (
          selector !== undefined &&
          (typeof selector !== "string" || selector.length === 0 || selector.length > 2048)
        )
          errors.push(`taskContract.secrets[${i}].selector must be a bounded non-empty string`);
        if (
          formAction !== undefined &&
          (typeof formAction !== "string" ||
            formAction.length === 0 ||
            formAction.length > 2048 ||
            originOf(formAction) === null)
        )
          errors.push(`taskContract.secrets[${i}].formAction must be a bounded non-empty URL`);
        if (
          typeof name === "string" &&
          (kind === "SECRET" || kind === "PII" || kind === "CREDENTIAL") &&
          Array.isArray(origins) &&
          Array.isArray(fieldTypes)
        ) {
          secrets.push({
            name,
            kind,
            origins: [...origins] as string[],
            fieldTypes: [...fieldTypes] as string[],
            ...(typeof selector === "string" ? { selector } : {}),
            ...(typeof formAction === "string" ? { formAction } : {}),
          });
        }
      }
    }
  }

  let origins: OriginAllowances | undefined;
  const originsInput = input["origins"];
  if (originsInput !== undefined) {
    if (!isRecord(originsInput)) {
      errors.push("taskContract.origins must be an object");
    } else {
      rejectUnknownKeys(originsInput, ORIGIN_KEYS, "taskContract.origins", errors);
      const built: Record<string, readonly string[]> = {};
      for (const key of ORIGIN_KEYS) {
        const value = originsInput[key];
        if (value !== undefined) {
          if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
            errors.push(`taskContract.origins.${key} must be a string array`);
          } else {
            built[key] = [...(value as string[])];
          }
        }
      }
      if (Object.keys(built).length > 0) {
        origins = built as OriginAllowances;
      }
    }
  }

  let budgets: BudgetConfig | undefined;
  const budgetsInput = input["budgets"];
  if (budgetsInput !== undefined) {
    if (!isRecord(budgetsInput)) {
      errors.push("taskContract.budgets must be an object");
    } else {
      rejectUnknownKeys(budgetsInput, BUDGET_KEYS, "taskContract.budgets", errors);
      const built: Record<string, number> = {};
      for (const key of BUDGET_KEYS) {
        const value = budgetsInput[key];
        if (value !== undefined) {
          if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
            errors.push(`taskContract.budgets.${key} must be a non-negative number`);
          } else {
            built[key] = value;
          }
        }
      }
      if (Object.keys(built).length > 0) {
        budgets = built as BudgetConfig;
      }
    }
  }

  let approval: ApprovalConfig | undefined;
  const approvalInput = input["approval"];
  if (approvalInput !== undefined) {
    if (!isRecord(approvalInput)) {
      errors.push("taskContract.approval must be an object");
    } else {
      rejectUnknownKeys(approvalInput, APPROVAL_KEYS, "taskContract.approval", errors);
      const built: Record<string, unknown> = {};
      const required = approvalInput["required"];
      if (required !== undefined) {
        if (typeof required !== "boolean") {
          errors.push("taskContract.approval.required must be a boolean");
        } else {
          built["required"] = required;
        }
      }
      const timeoutMs = approvalInput["timeoutMs"];
      if (timeoutMs !== undefined) {
        if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs < 0) {
          errors.push("taskContract.approval.timeoutMs must be a non-negative number");
        } else {
          built["timeoutMs"] = timeoutMs;
        }
      }
      if (Object.keys(built).length > 0) {
        approval = built as ApprovalConfig;
      }
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  const value: TaskContract = {
    task: task as string,
    ...(capabilities !== undefined ? { capabilities } : {}),
    ...(secrets !== undefined ? { secrets } : {}),
    ...(origins !== undefined ? { origins } : {}),
    ...(budgets !== undefined ? { budgets } : {}),
    ...(approval !== undefined ? { approval } : {}),
  };
  const branded = Object.defineProperty(value, VALIDATED_TASK_CONTRACT, {
    value: true as const,
    enumerable: false,
  }) as ValidatedTaskContract;
  return { ok: true, value: deepFreeze(branded) };
}

/** Recursively freeze every nested object and array (INV-01, TB1 immutability). */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const key of Object.getOwnPropertyNames(value)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}
