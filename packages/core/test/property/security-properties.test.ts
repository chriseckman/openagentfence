import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  RedactionRegistry,
  REASON_CODES,
  applyRiskSignal,
  compareIntentState,
  compileTaskContract,
  envelopeAllowsAtLeast,
  evaluateNetworkMutation,
  isIntentExpired,
  isValidatedTaskContract,
  riskAggregator,
  runGuardProvider,
  validateActionIntent,
  validateGuardClassification,
  validateNetworkMutation,
  validateScanResult,
  validateTaskContract,
} from "../../src/index.js";
import type {
  ActionIntent,
  ActionShape,
  CanonicalAction,
  GuardClassificationRequest,
  GuardExecutionConstraints,
  GuardModelProvider,
  IntentMismatchCode,
  IntentStateSnapshot,
  NetworkIntentCorrelationStatus,
  NetworkInitiator,
  NetworkMutation,
  NetworkSurface,
  ActionType,
  EnvelopeNarrowing,
  NavigationMode,
  RiskState,
  RiskSignal,
  ScanResult,
  ScannerVerdict,
  SessionRisk,
} from "../../src/index.js";
import { mkFinding, mkScanResult } from "../helpers.js";
import { propertyOptions } from "./config.js";

const VERDICTS = ["allow", "warn", "sanitize", "approve", "block"] as const;
const RISK_RANK: Readonly<Record<RiskState, number>> = {
  NORMAL: 0,
  RESTRICTED: 1,
  READ_ONLY: 2,
  QUARANTINED: 3,
};
const redactor = new RedactionRegistry();

describe("OAF-TEST-013 core security properties", () => {
  it("keeps fixed precedence under arbitrary semantic evidence", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<"critical" | "policy" | "secret" | "session">(
          "critical",
          "policy",
          "secret",
          "session",
        ),
        fc.array(fc.constantFrom<ScannerVerdict>(...VERDICTS), { maxLength: 12 }),
        (layer, semanticVerdicts) => {
          const baseline = aggregationInput(layer, []);
          const withSemantic = aggregationInput(layer, semanticResults(semanticVerdicts));
          const expected = riskAggregator.aggregate(baseline);
          const actual = riskAggregator.aggregate(withSemantic);
          expect(actual.verdict).toBe(expected.verdict);
          expect(actual.decidedBy?.layer).toBe(expected.decidedBy?.layer);
        },
      ),
      propertyOptions("core.aggregator-precedence"),
    );
  });

  it("is idempotent and authority-order-independent", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom<ScannerVerdict>(...VERDICTS), { minLength: 1, maxLength: 12 }),
        (verdicts) => {
          const results = verdicts.map((verdict, index) =>
            scanResult(index % 2 === 0 ? "deterministic" : "semantic", verdict, index),
          );
          const input = aggregationInput("none", results);
          const first = riskAggregator.aggregate(input);
          const repeated = riskAggregator.aggregate(input);
          const reversed = riskAggregator.aggregate({
            ...input,
            scanResults: [...results].reverse(),
          });
          expect(repeated).toEqual(first);
          expect(reversed.verdict).toBe(first.verdict);
          expect(reversed.decidedBy?.layer).toBe(first.decidedBy?.layer);
          expect([...reversed.reasons].sort()).toEqual([...first.reasons].sort());
        },
      ),
      propertyOptions("core.aggregator-idempotence-order"),
    );
  });

  it("never lets probabilistic output grant or recover authority", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom<ScannerVerdict>(...VERDICTS), { maxLength: 20 }),
        (verdicts) => {
          const semantic = semanticResults(verdicts);
          for (const layer of ["critical", "policy", "secret", "session"] as const) {
            const before = riskAggregator.aggregate(aggregationInput(layer, []));
            const after = riskAggregator.aggregate(aggregationInput(layer, semantic));
            expect(after.verdict).toBe(before.verdict);
            expect(after.decidedBy?.layer).toBe(before.decidedBy?.layer);
          }
        },
      ),
      propertyOptions("core.probabilistic-non-authority"),
    );
  });

  it("keeps compound envelope narrowing shrink-only", () => {
    fc.assert(
      fc.property(
        narrowingArbitrary(),
        narrowingArbitrary(),
        actionArbitrary(),
        (firstPatch, secondPatch, action) => {
          const base = broadEnvelope();
          const first = base.narrow(firstPatch);
          const second = first.narrow(secondPatch);
          expect(envelopeAllowsAtLeast(base, first)).toBe(true);
          expect(envelopeAllowsAtLeast(first, second)).toBe(true);
          expect(envelopeAllowsAtLeast(base, second)).toBe(true);
          if (second.evaluate(action).allowed) expect(base.evaluate(action).allowed).toBe(true);
        },
      ),
      propertyOptions("core.envelope-shrink-only"),
    );
  });

  it("keeps risk state and score monotonic for every signal sequence", () => {
    const signals: readonly RiskSignal[] = [
      "hidden_injection",
      "cross_origin_redirect",
      "secret_requested",
      "unrelated_tab",
      "unexpected_download",
      "high_confidence_injection",
      "critical_finding",
    ];
    fc.assert(
      fc.property(
        fc.constantFrom<RiskState>("NORMAL", "RESTRICTED", "READ_ONLY", "QUARANTINED"),
        fc.integer({ min: 0, max: 500 }),
        fc.array(fc.constantFrom(...signals), { maxLength: 100 }),
        (state, score, sequence) => {
          let risk: SessionRisk = { state, score };
          for (const signal of sequence) {
            const next = applyRiskSignal(risk, signal).current;
            expect(RISK_RANK[next.state]).toBeGreaterThanOrEqual(RISK_RANK[risk.state]);
            expect(next.score).toBeGreaterThanOrEqual(risk.score);
            risk = next;
          }
        },
      ),
      propertyOptions("core.risk-monotonicity"),
    );
  });

  it("invalidates every generated security-relevant intent mutation", () => {
    fc.assert(
      fc.property(intentMutationArbitrary(), (mutation) => {
        const bound = actionIntent();
        const before = JSON.stringify(bound);
        const mismatches = compareIntentState(bound, mutation.snapshot);
        expect(mismatches).toContain(mutation.code);
        expect(JSON.stringify(bound)).toBe(before);
      }),
      propertyOptions("core.action-intent-invalidation"),
    );
  });

  it("treats the exact generated expiry boundary as invalid", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 2_000_000_000 }),
        fc.integer({ min: 1, max: 60_000 }),
        (createdAt, ttl) => {
          const intent = actionIntent({ createdAt, expiresAt: createdAt + ttl });
          expect(isIntentExpired(intent, createdAt + ttl - 1)).toBe(false);
          expect(isIntentExpired(intent, createdAt + ttl)).toBe(true);
          expect(isIntentExpired(intent, createdAt + ttl + 1)).toBe(true);
        },
      ),
      propertyOptions("core.action-intent-expiry"),
    );
  });

  it("never promotes observed or unavailable network surfaces to continue", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<NetworkSurface>(
          "navigation",
          "redirect",
          "form",
          "fetch",
          "headers",
          "websocket",
          "send_beacon",
          "service_worker",
          "upload",
          "download",
          "popup",
          "webmcp",
        ),
        fc.constantFrom<NetworkInitiator>(
          "authorized_action",
          "page_script",
          "form",
          "redirect",
          "webmcp",
          "service_worker",
          "unknown",
        ),
        fc.constantFrom<"observed_only" | "unavailable">("observed_only", "unavailable"),
        (surface, initiator, enforcement) => {
          const decision = evaluateNetworkMutation({
            mutation: networkMutation({ surface, initiator, enforcement }),
            envelope: networkEnvelope(),
            riskState: "NORMAL",
            egressInspection: cleanEgress,
          });
          expect(decision.verdict).toBe("observe_only_gap");
          expect(decision.reasons).toContain(REASON_CODES.network_enforcement_unavailable);
        },
      ),
      propertyOptions("core.network-capability-monotonicity"),
    );
  });

  it("never treats intent correlation as network authority", () => {
    fc.assert(
      fc.property(
        fc.constantFrom<NetworkIntentCorrelationStatus>("none", "matched", "mismatched", "expired"),
        fc.constantFrom<NetworkInitiator>(
          "authorized_action",
          "page_script",
          "form",
          "redirect",
          "unknown",
        ),
        (status, initiator) => {
          const decision = evaluateNetworkMutation({
            mutation: networkMutation({
              initiator,
              destination: "http://127.0.0.1/private",
              enforcement: "enforced",
            }),
            envelope: networkEnvelope(),
            riskState: "NORMAL",
            egressInspection: cleanEgress,
            correlation: {
              status,
              ...(status === "none" ? {} : { intentId: "intent-1" }),
              reasons:
                status === "mismatched"
                  ? [REASON_CODES.action_intent_mismatch]
                  : status === "expired"
                    ? [REASON_CODES.action_intent_expired]
                    : [],
            },
          });
          expect(decision.verdict).toBe("block");
          expect(decision.reasons).toContain(REASON_CODES.private_network_destination);
        },
      ),
      propertyOptions("core.network-correlation-non-authority"),
    );
  });

  it("bounds and cancels arbitrary provider calls without granting authority", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("oversized", "cancelled", "budget", "malformed"),
        fc.string({ maxLength: 256 }),
        fc.jsonValue(),
        async (mode, text, providerValue) => {
          let calls = 0;
          const provider: GuardModelProvider = {
            name: "property-provider",
            model: "property-provider",
            makesExternalCalls: false,
            classify: async () => {
              calls += 1;
              return providerValue;
            },
          };
          const controller = new AbortController();
          const payload =
            mode === "oversized" && Buffer.byteLength(text, "utf8") === 0 ? "x" : text;
          if (mode === "cancelled") controller.abort();
          const request = guardRequest(payload);
          const constraints = guardConstraints(controller.signal, {
            ...(mode === "oversized"
              ? { maxInputBytes: Math.max(0, Buffer.byteLength(payload, "utf8") - 1) }
              : {}),
            ...(mode === "budget" ? { remainingCalls: 0 } : {}),
          });
          const outcome = await runGuardProvider(provider, request, constraints);
          if (mode === "oversized") expect(outcome).toEqual({ ok: false, kind: "oversized" });
          if (mode === "cancelled") expect(outcome).toEqual({ ok: false, kind: "cancelled" });
          if (mode === "budget") expect(outcome).toEqual({ ok: false, kind: "budget_exhausted" });
          if (mode === "malformed") {
            expect(!outcome.ok || validateGuardClassification(outcome.value) !== null).toBe(true);
          } else {
            expect(calls).toBe(0);
          }
        },
      ),
      propertyOptions("core.provider-bounds-cancellation"),
    );
  });

  it("safely rejects or validates arbitrary contract-boundary JSON", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(() => validateActionIntent(value)).not.toThrow();
        expect(() => validateNetworkMutation(value)).not.toThrow();
        expect(() => validateGuardClassification(value)).not.toThrow();
        expect(() => validateScanResult(value)).not.toThrow();
        const contract = validateTaskContract(value);
        if (contract.ok) {
          expect(isValidatedTaskContract(contract.value)).toBe(true);
          expect(Object.isFrozen(contract.value)).toBe(true);
        } else {
          expect(contract.errors.length).toBeGreaterThan(0);
        }
      }),
      propertyOptions("core.arbitrary-contracts"),
    );
  });
});

function semanticResults(verdicts: readonly ScannerVerdict[]): readonly ScanResult[] {
  return verdicts.map((verdict, index) => scanResult("semantic", verdict, index));
}

function scanResult(
  kind: "deterministic" | "semantic",
  verdict: ScannerVerdict,
  index: number,
): ScanResult {
  return mkScanResult(`${kind}-${index}`, kind, verdict, [
    mkFinding(`${kind}-${index}`, kind === "semantic" ? "injection" : "heuristic", {
      recommendedAction: verdict,
    }),
  ]);
}

function aggregationInput(
  layer: "critical" | "policy" | "secret" | "session" | "none",
  extra: readonly ScanResult[],
) {
  const scanResults: ScanResult[] = [...extra];
  if (layer === "critical") scanResults.unshift(scanResult("deterministic", "block", 999));
  return {
    scanResults,
    policyDecision: {
      verdict: layer === "policy" ? ("BLOCK" as const) : ("ALLOW" as const),
      reasons:
        layer === "policy"
          ? [REASON_CODES.destination_not_allowed]
          : layer === "secret"
            ? [REASON_CODES.secret_sink_not_allowed]
            : [],
      matchedRules: layer === "policy" ? ["property-policy"] : [],
      policyHash: "property-policy-hash",
    },
    riskState: layer === "session" ? ("QUARANTINED" as const) : ("NORMAL" as const),
    score: layer === "session" ? 120 : 0,
    budgetsExhausted: false,
  };
}

function broadEnvelope() {
  const result = validateTaskContract({
    task: "property task",
    capabilities: {
      navigation: "allowlist",
      downloads: true,
      uploads: true,
      purchases: true,
      messaging: true,
      destructiveActions: true,
      credentials: true,
      executeScript: true,
      privateNetwork: true,
      externalCommunication: true,
    },
    origins: { allow: ["https://a.example", "https://b.example"] },
  });
  if (!result.ok) throw new TypeError("invalid property task contract");
  return compileTaskContract(result.value);
}

function narrowingArbitrary(): fc.Arbitrary<EnvelopeNarrowing> {
  return fc.record(
    {
      navigation: fc.constantFrom<NavigationMode>("allowlist", "same-site", "same-origin", "none"),
      downloads: fc.boolean(),
      uploads: fc.boolean(),
      purchases: fc.boolean(),
      messaging: fc.boolean(),
      destructiveActions: fc.boolean(),
      credentials: fc.boolean(),
      executeScript: fc.boolean(),
      privateNetwork: fc.boolean(),
      externalCommunication: fc.boolean(),
      allowedOrigins: fc.subarray(["https://a.example", "https://b.example"]),
    },
    { requiredKeys: [] },
  );
}

function actionArbitrary(): fc.Arbitrary<ActionShape> {
  return fc.record(
    {
      type: fc.constantFrom<ActionType>(
        "READ",
        "CLICK",
        "NAVIGATE",
        "SUBMIT",
        "UPLOAD",
        "DOWNLOAD",
        "PURCHASE",
        "MESSAGE",
        "EXECUTE_SCRIPT",
      ),
      destination: fc.constantFrom(
        "https://a.example/path",
        "https://b.example/path",
        "https://evil.example/path",
        "http://127.0.0.1/private",
      ),
      target: fc.constantFrom({ origin: "https://a.example" }, { origin: "https://b.example" }),
    },
    { requiredKeys: ["type"] },
  );
}

function actionIntent(overrides: Partial<ActionIntent> = {}): ActionIntent {
  return {
    intentId: "intent-1",
    actionId: "action-1",
    action: {
      type: "NAVIGATE",
      destination: "https://a.example/checkout",
      instructionProvenance: { trust: "application" },
    } satisfies CanonicalAction,
    observation: { browserContextId: "context-1", pageId: "page-1", revision: 1 },
    target: {
      selector: "#checkout",
      element: "button-1",
      frame: "frame-1",
      origin: "https://a.example",
    },
    frameOrigin: "https://a.example",
    destination: "https://a.example/checkout",
    navigationOrigin: "link",
    formAction: "https://a.example/submit",
    securityAttributes: { href: "/checkout", type: "submit" },
    visibility: "visible",
    policyHash: "policy-1",
    operationHash: "operation-1",
    createdAt: 1_000,
    expiresAt: 2_000,
    ...overrides,
  };
}

function intentSnapshot(overrides: Partial<IntentStateSnapshot> = {}): IntentStateSnapshot {
  return {
    observation: { browserContextId: "context-1", pageId: "page-1", revision: 1 },
    target: {
      selector: "#checkout",
      element: "button-1",
      frame: "frame-1",
      origin: "https://a.example",
    },
    frameOrigin: "https://a.example",
    destination: "https://a.example/checkout",
    navigationOrigin: "link",
    formAction: "https://a.example/submit",
    securityAttributes: { href: "/checkout", type: "submit" },
    visibility: "visible",
    policyHash: "policy-1",
    operationHash: "operation-1",
    ...overrides,
  };
}

function intentMutationArbitrary(): fc.Arbitrary<{
  readonly code: IntentMismatchCode;
  readonly snapshot: IntentStateSnapshot;
}> {
  return fc.integer({ min: 2, max: 100_000 }).chain((suffix) =>
    fc.constantFrom(
      {
        code: "observation" as const,
        snapshot: intentSnapshot({
          observation: { browserContextId: "context-1", pageId: "page-1", revision: suffix },
        }),
      },
      {
        code: "target" as const,
        snapshot: intentSnapshot({ target: { selector: `#other-${suffix}` } }),
      },
      {
        code: "frame" as const,
        snapshot: intentSnapshot({ frameOrigin: `https://frame-${suffix}.example` }),
      },
      {
        code: "destination" as const,
        snapshot: intentSnapshot({ destination: `https://destination-${suffix}.example` }),
      },
      {
        code: "navigation_origin" as const,
        snapshot: intentSnapshot({ navigationOrigin: "direct" }),
      },
      {
        code: "form_action" as const,
        snapshot: intentSnapshot({ formAction: `https://form-${suffix}.example` }),
      },
      {
        code: "security_attributes" as const,
        snapshot: intentSnapshot({ securityAttributes: { href: `/other-${suffix}` } }),
      },
      {
        code: "visibility" as const,
        snapshot: intentSnapshot({ visibility: `hidden-${suffix}` }),
      },
      { code: "policy" as const, snapshot: intentSnapshot({ policyHash: `policy-${suffix}` }) },
      {
        code: "operation" as const,
        snapshot: intentSnapshot({ operationHash: `operation-${suffix}` }),
      },
    ),
  );
}

function networkMutation(overrides: Partial<NetworkMutation> = {}): NetworkMutation {
  return {
    surface: "fetch",
    initiator: "page_script",
    origin: "https://a.example",
    destination: "https://a.example/data",
    enforcement: "enforced",
    provenance: { trust: "web", timestamp: "2026-08-20T00:00:00.000Z" },
    ...overrides,
  };
}

function networkEnvelope() {
  const result = validateTaskContract({
    task: "network property",
    capabilities: { navigation: "allowlist", externalCommunication: true },
    origins: { allow: ["https://a.example"] },
  });
  if (!result.ok) throw new TypeError("invalid network property contract");
  return compileTaskContract(result.value);
}

const cleanEgress = {
  verdict: "allow" as const,
  reasons: [],
  inspectedBytes: 0,
  matchCount: 0,
};

function guardRequest(text: string): GuardClassificationRequest {
  return {
    role: "text_injection",
    excerpts: [],
    taskSummary: redactor.redact(text),
    localeHints: ["en"],
  };
}

function guardConstraints(
  signal: AbortSignal,
  overrides: Partial<GuardExecutionConstraints> = {},
): GuardExecutionConstraints {
  return {
    signal,
    deadline: Date.now() + 10_000,
    maxInputBytes: 10_000,
    maxOutputBytes: 10_000,
    ...overrides,
  };
}
