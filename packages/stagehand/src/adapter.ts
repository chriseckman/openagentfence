import {
  compareIntentState,
  DEFAULT_NETWORK_CAPABILITIES,
  fingerprint,
  isIntentExpired,
  type ActionIntent,
  type CanonicalAction,
  type IntentStateSnapshot,
  type SecuritySession,
  type UntrustedContent,
} from "@openagentfence/core";
import { randomUUID } from "node:crypto";
import type { StagehandLike, StagehandObserveResult } from "./types.js";

/** Stable fail-closed reason codes emitted by the Stagehand wrapper. */
export const STAGEHAND_SECURITY_ERROR_CODES = [
  "invalid_observe_response",
  "no_authorized_action",
  "ambiguous_authorized_action",
  "authorized_action_not_executable",
  "state_revalidation_unavailable",
  "action_intent_expired",
  "action_intent_mismatch",
  "extract_unavailable",
  "untrusted_output_invalid",
  "untrusted_output_oversized",
  "unsupported_file_effect",
  "disabled_path",
] as const;

export type StagehandSecurityErrorCode = (typeof STAGEHAND_SECURITY_ERROR_CODES)[number];

export class StagehandSecurityError extends Error {
  readonly code: StagehandSecurityErrorCode;

  constructor(code: StagehandSecurityErrorCode, message: string) {
    super(message);
    this.name = "StagehandSecurityError";
    this.code = code;
  }
}

export type StagehandSurfaceStatus = "hooked" | "read_only" | "disabled";

/** Data-only v4 coverage ledger; new public execution paths must be classified. */
export const STAGEHAND_SURFACE_COVERAGE = Object.freeze([
  { surface: "observe", status: "read_only" },
  { surface: "act", status: "hooked" },
  { surface: "extract", status: "hooked" },
  { surface: "screenshot_first", status: "hooked" },
  { surface: "form_submission", status: "disabled" },
  { surface: "upload", status: "disabled" },
  { surface: "download", status: "disabled" },
  { surface: "page_control", status: "disabled" },
  { surface: "agent", status: "disabled" },
  { surface: "batch", status: "disabled" },
  { surface: "webmcp_list", status: "disabled" },
  { surface: "webmcp_invoke", status: "disabled" },
] as const satisfies readonly {
  readonly surface: string;
  readonly status: StagehandSurfaceStatus;
}[]);

/** No v4 hook exposes independently validated browser/WebMCP network effects. */
export const STAGEHAND_NETWORK_CAPABILITIES = DEFAULT_NETWORK_CAPABILITIES;

/** Adapter-provided deterministic Stagehand target/page resolver (ADR-0010). */
export interface StagehandStateResolver {
  snapshot(action: StagehandObserveResult): Promise<IntentStateSnapshot>;
}

export interface StagehandWrapOptions {
  readonly stateResolver?: StagehandStateResolver;
  readonly maxOutputBytes?: number;
}

export interface StagehandAuthorizationResult {
  readonly action: CanonicalAction;
  readonly allowed: boolean;
  readonly reasons: readonly string[];
}

export function normalizeObserveResult(result: unknown): CanonicalAction {
  const structured = parseObservedAction(result);
  if (structured === undefined) return { type: "UNKNOWN", instructionProvenance: { trust: "web" } };
  const type = actionTypeOf(structured.method);
  return {
    type,
    ...(type === "NAVIGATE" ? { navigationOrigin: "direct" as const } : {}),
    instructionProvenance: { trust: "web" },
    target: { element: structured.selector },
    ...(type === "NAVIGATE" && structured.arguments?.[0] !== undefined
      ? { destination: structured.arguments[0] }
      : {}),
    ...(structured.arguments !== undefined ? { data: structured.arguments } : {}),
    raw: structured,
  };
}

function actionTypeOf(method: string | undefined): CanonicalAction["type"] {
  switch (method?.toLowerCase()) {
    case "click":
      return "CLICK";
    case "fill":
      return "FILL";
    case "type":
    case "press":
      return "TYPE";
    case "selectoption":
      return "CLICK";
    case "setinputfiles":
      return "UPLOAD";
    case "goto":
      return "NAVIGATE";
    default:
      return "UNKNOWN";
  }
}

function parseObservedAction(value: unknown): StagehandObserveResult | undefined {
  if (!isRecord(value)) return undefined;
  const selector = value["selector"];
  const description = value["description"];
  const method = value["method"];
  const args = value["arguments"];
  const parsedArgs =
    args === undefined ? undefined : boundedStringArgs(args) ? [...args] : undefined;
  if (
    typeof selector !== "string" ||
    selector.length === 0 ||
    selector.length > 2048 ||
    typeof description !== "string" ||
    description.length === 0 ||
    description.length > 4096 ||
    (method !== undefined &&
      (typeof method !== "string" || method.length === 0 || method.length > 64)) ||
    (args !== undefined && parsedArgs === undefined)
  ) {
    return undefined;
  }
  return Object.freeze({
    selector,
    description,
    ...(typeof method === "string" ? { method } : {}),
    ...(parsedArgs !== undefined ? { arguments: parsedArgs } : {}),
  });
}

function boundedStringArgs(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 20 &&
    value.every((arg) => typeof arg === "string" && arg.length <= 4096)
  );
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function executableObservedAction(value: unknown): StagehandObserveResult | undefined {
  if (!isRecord(value) || typeof value["method"] !== "string") return undefined;
  return parseObservedAction(value);
}

export function stagehandAdapter(stagehand: StagehandLike) {
  return {
    async observe(instruction?: string): Promise<readonly CanonicalAction[]> {
      const response = await stagehand.observe(instruction);
      if (!isRecord(response) || !Array.isArray(response["data"])) {
        throw new StagehandSecurityError(
          "invalid_observe_response",
          "Stagehand observe response failed runtime validation",
        );
      }
      return response["data"].map(normalizeObserveResult);
    },
  };
}

export async function authorizeActions(
  session: SecuritySession,
  candidates: readonly CanonicalAction[],
): Promise<readonly StagehandAuthorizationResult[]> {
  const out: StagehandAuthorizationResult[] = [];
  for (const action of candidates) {
    const decision = await session.authorize(action);
    out.push({ action, allowed: decision.verdict === "ALLOW", reasons: decision.reasons });
  }
  return out;
}

/**
 * Secure Stagehand v4 surface. `act()` is disabled without a deterministic
 * resolver; it never falls back to model inference or mutable page data.
 */
export function wrapStagehand(
  session: SecuritySession,
  stagehand: StagehandLike,
  options: StagehandWrapOptions = {},
) {
  const adapter = stagehandAdapter(stagehand);
  const maxOutputBytes = options.maxOutputBytes ?? 65_536;

  const actOnce = async (instruction: string, retried: boolean): Promise<unknown> => {
    if (options.stateResolver === undefined) {
      throw new StagehandSecurityError(
        "state_revalidation_unavailable",
        "Stagehand act is disabled without a deterministic state resolver; use the recorded escape hatch",
      );
    }
    const candidates = await adapter.observe(instruction);
    if (candidates.length === 0) {
      throw new StagehandSecurityError("no_authorized_action", "no authorized structured action");
    }
    if (candidates.length !== 1) {
      throw new StagehandSecurityError(
        "ambiguous_authorized_action",
        "multiple structured candidates require explicit application selection",
      );
    }
    const candidate = candidates[0];
    if (candidate === undefined) {
      throw new StagehandSecurityError("no_authorized_action", "no authorized structured action");
    }
    const action = executableObservedAction(candidate.raw);
    if (action === undefined) {
      throw new StagehandSecurityError(
        "authorized_action_not_executable",
        "authorized candidate lacks a validated structured operation",
      );
    }
    const state = await options.stateResolver.snapshot(action);
    if (
      candidate.type === "SUBMIT" ||
      candidate.type === "UPLOAD" ||
      candidate.type === "DOWNLOAD" ||
      state.formAction !== undefined
    ) {
      throw new StagehandSecurityError(
        "unsupported_file_effect",
        "Stagehand form, upload, and download effects are disabled without exact metadata hooks",
      );
    }
    const now = Date.now();
    // The observed structured operation is the only Stagehand executor input.
    // Resolver-provided operation hashes are not authority: derive the hash
    // locally so a hostile or stale resolver cannot bind a different method or
    // argument vector under the same snapshot.
    const operationHash = fingerprint(action);
    const intent: ActionIntent = {
      intentId: `stagehand-intent-${randomUUID()}`,
      actionId: `stagehand-action-${randomUUID()}`,
      action: candidate,
      observation: state.observation,
      target: state.target,
      ...(state.frameOrigin !== undefined ? { frameOrigin: state.frameOrigin } : {}),
      ...(state.destination !== undefined ? { destination: state.destination } : {}),
      securityAttributes: state.securityAttributes,
      visibility: state.visibility,
      policyHash: state.policyHash,
      operationHash,
      createdAt: now,
      expiresAt: now + 5_000,
    };
    const bound = await session.authorizeBound(candidate, intent);
    if (bound.authorized === undefined) {
      throw new StagehandSecurityError(
        "no_authorized_action",
        "state-bound authorization was blocked",
      );
    }
    const currentState = await options.stateResolver.snapshot(action);
    const current: IntentStateSnapshot = { ...currentState, operationHash };
    const mismatch = isIntentExpired(bound.authorized.intent)
      ? "action_intent_expired"
      : compareIntentState(bound.authorized.intent, current).length > 0
        ? "action_intent_mismatch"
        : undefined;
    if (mismatch !== undefined) {
      session.recordRevalidation(mismatch, bound.authorized.intent.intentId);
      if (!retried) return actOnce(instruction, true);
      throw new StagehandSecurityError(mismatch, "Stagehand state changed during bounded retry");
    }
    return session.executeAuthorizedWith(bound.authorized, {
      execute: () => stagehand.act(action),
    });
  };

  return {
    act: (instruction: string) => actOnce(instruction, false),
    authorizeActions: (candidates: readonly CanonicalAction[]) =>
      authorizeActions(session, candidates),
    async extract(input: unknown): Promise<UntrustedContent> {
      if (stagehand.extract === undefined) {
        throw new StagehandSecurityError("extract_unavailable", "Stagehand extract is unavailable");
      }
      const output = await stagehand.extract(input);
      if (typeof output !== "string") {
        throw new StagehandSecurityError(
          "untrusted_output_invalid",
          "Stagehand extract must return text",
        );
      }
      try {
        return await session.inspectUntrustedText(output, maxOutputBytes);
      } catch (error) {
        if (error instanceof RangeError) {
          throw new StagehandSecurityError("untrusted_output_oversized", error.message);
        }
        throw error;
      }
    },
    async screenshotFirstContext(): Promise<{
      readonly screenshot: unknown;
      readonly visibleText: string;
    }> {
      const result = await session.observe();
      const observation = result.observation;
      if (observation.screenshot === undefined) {
        throw new StagehandSecurityError(
          "disabled_path",
          "screenshot-first mode requires adapter screenshot capture",
        );
      }
      return {
        screenshot: observation.screenshot,
        visibleText: (observation.probe?.nodes ?? [])
          .filter((node) => node.inViewport && !node.hidden && node.text.length > 0)
          .map((node) => node.text)
          .join("\n"),
      };
    },
    disabled(surface: string): never {
      throw new StagehandSecurityError(
        "disabled_path",
        `${surface} is disabled; use the recorded escape hatch`,
      );
    },
    webmcp: Object.freeze({
      list(): never {
        throw new StagehandSecurityError(
          "disabled_path",
          "WebMCP listing is disabled without manifest/output/network hooks",
        );
      },
      invoke(): never {
        throw new StagehandSecurityError(
          "disabled_path",
          "WebMCP invocation is disabled without manifest/output/network hooks",
        );
      },
    }),
  };
}
