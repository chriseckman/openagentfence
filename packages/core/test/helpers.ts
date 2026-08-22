import { DEFAULT_NETWORK_CAPABILITIES, RedactionRegistry } from "../src/index.js";
import { secureDefaultEnvelope } from "../src/index.js";
import { provenanced } from "../src/index.js";
import type {
  ActionType,
  CanonicalAction,
  Finding,
  PhasePayload,
  ScanResult,
  ScannerVerdict,
  SecurityContext,
  SecurityPhase,
  BrowserAdapter,
} from "../src/index.js";

export const redactor = new RedactionRegistry();

export function mkAction(
  type: ActionType,
  overrides: Omit<Partial<CanonicalAction>, "data"> & { readonly data?: unknown } = {},
): CanonicalAction {
  const { data, ...rest } = overrides;
  return {
    type,
    instructionProvenance: { trust: "application" },
    ...(data !== undefined ? { data: provenanced(data, { trust: "application" }) } : {}),
    ...rest,
  };
}

export function mkFinding(id: string, category: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    category,
    title: category,
    description: category,
    source: { type: "tool" },
    provenance: { trust: "web" },
    evidence: redactor.redact(`evidence for ${category}`),
    recommendedAction: "warn",
    ...overrides,
  };
}

export function mkScanResult(
  scanner: string,
  kind: "deterministic" | "semantic",
  verdict: ScannerVerdict,
  findings: readonly Finding[],
  overrides: Partial<ScanResult> = {},
): ScanResult {
  return {
    scanner,
    kind,
    verdict,
    severity: overrides.severity ?? "low",
    findings,
    ...overrides,
  };
}

export function mkContext(
  phase: SecurityPhase,
  payload: PhasePayload = { kind: "none" },
  overrides: Partial<SecurityContext> = {},
): SecurityContext {
  return {
    phase,
    sessionId: "test-session",
    taskContract: { task: "test" },
    envelope: secureDefaultEnvelope("test"),
    riskState: "NORMAL",
    payload,
    provenance: { trust: "web" },
    redactor,
    deadline: Date.now() + 10_000,
    signal: new AbortController().signal,
    ...overrides,
  };
}

export function fakeAdapter(overrides: Partial<BrowserAdapter> = {}): BrowserAdapter {
  return {
    capabilities: {
      route: false,
      network: DEFAULT_NETWORK_CAPABILITIES,
      navigationEvents: true,
      downloadEvents: true,
      popupEvents: true,
      screenshot: false,
      ariaSnapshot: false,
    },
    observe: async () => ({
      url: "https://example.com",
      origin: "https://example.com",
      frames: [],
      provenance: { trust: "web" },
    }),
    executeAuthorized: async () => undefined,
    subscribe: () => () => {},
    rawPage: () => ({ __raw: true }),
    ...overrides,
  };
}
