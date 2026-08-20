import type { GuardModelProvider, GuardRole } from "@openagentfence/core";

/** Provider names reserved by the v0.1 application-owned factory. */
export const GUARD_PROVIDER_NAMES = [
  "custom",
  "openai-compatible",
  "ollama",
  "opencode",
  "anthropic",
  "google",
  "xai",
] as const;

export type GuardProviderName = (typeof GUARD_PROVIDER_NAMES)[number];

export type GuardProviderCallback = GuardModelProvider["classify"];

/** Shared application-owned options. No option is read from the environment. */
export interface GuardProviderOptions {
  readonly model: string;
  readonly apiKey?: string;
  readonly baseUrl?: string;
  readonly timeoutMs?: number;
  readonly roles?: readonly GuardRole[];
  readonly fallback?: GuardModelProvider;
}

export interface CustomGuardProviderOptions extends GuardProviderOptions {
  readonly callback: GuardProviderCallback;
  readonly makesExternalCalls: boolean;
}

export type GuardProviderConstructionFailure = "invalid_options" | "provider_unavailable";

/** Stable value-free construction failure. */
export class GuardProviderConstructionError extends Error {
  readonly code: GuardProviderConstructionFailure;

  constructor(code: GuardProviderConstructionFailure) {
    super(
      code === "provider_unavailable"
        ? "guard provider unavailable"
        : "invalid guard provider options",
    );
    this.name = "GuardProviderConstructionError";
    this.code = code;
  }
}

const ROLES = new Set<GuardRole>(["text_injection", "visual_injection", "task_alignment"]);

export interface ValidatedGuardProviderOptions {
  readonly model: string;
  readonly timeoutMs: number;
  readonly roles: ReadonlySet<GuardRole>;
  readonly baseUrl?: string;
  readonly fallback?: GuardModelProvider;
}

export function validateProviderOptions(
  input: unknown,
  extraKeys: readonly string[] = [],
): ValidatedGuardProviderOptions {
  if (typeof input !== "object" || input === null || Array.isArray(input)) fail();
  const record = input as Record<string, unknown>;
  const allowed = new Set([
    "model",
    "apiKey",
    "baseUrl",
    "timeoutMs",
    "roles",
    "fallback",
    ...extraKeys,
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key))) fail();
  const model = record["model"];
  if (typeof model !== "string" || model.length === 0 || model.length > 256) fail();
  const apiKey = record["apiKey"];
  if (apiKey !== undefined && (typeof apiKey !== "string" || apiKey.length > 16_384)) fail();
  const baseUrl = record["baseUrl"];
  if (baseUrl !== undefined) {
    if (typeof baseUrl !== "string" || baseUrl.length === 0 || baseUrl.length > 2_048) fail();
    let parsed: URL;
    try {
      parsed = new URL(baseUrl);
    } catch {
      fail();
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") fail();
    if (
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== ""
    ) {
      fail();
    }
  }
  const timeoutMs = record["timeoutMs"] ?? 30_000;
  if (typeof timeoutMs !== "number") fail();
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) fail();
  const roleValues: unknown = record["roles"] ?? ["text_injection", "task_alignment"];
  if (!Array.isArray(roleValues) || roleValues.length === 0 || roleValues.length > ROLES.size)
    fail();
  const roles = new Set<GuardRole>();
  for (const role of roleValues) {
    if (typeof role !== "string" || !isGuardRole(role) || roles.has(role)) fail();
    roles.add(role);
  }
  const fallback = record["fallback"];
  if (fallback !== undefined && !isProvider(fallback)) fail();
  return Object.freeze({
    model,
    timeoutMs,
    roles,
    ...(baseUrl === undefined ? {} : { baseUrl }),
    ...(fallback === undefined ? {} : { fallback }),
  });
}

function isGuardRole(value: string): value is GuardRole {
  return ROLES.has(value as GuardRole);
}

function isProvider(value: unknown): value is GuardModelProvider {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const provider = value as Partial<GuardModelProvider>;
  return (
    typeof provider.name === "string" &&
    typeof provider.model === "string" &&
    typeof provider.makesExternalCalls === "boolean" &&
    typeof provider.classify === "function"
  );
}

function fail(): never {
  throw new GuardProviderConstructionError("invalid_options");
}
