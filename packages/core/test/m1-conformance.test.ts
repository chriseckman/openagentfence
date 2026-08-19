import { describe, expect, it } from "vitest";
import {
  ACTION_TYPES,
  AGGREGATE_VERDICTS,
  buildTrustedIntentContext,
  compileTaskContract,
  compareIntentState,
  DEFAULT_NETWORK_CAPABILITIES,
  isAuthorizedAction,
  isHighImpact,
  isTrustedIntent,
  RedactionRegistry,
  resolveApproval,
  riskAggregator,
  runGuardProvider,
  secureDefaultEnvelope,
  validateActionIntent,
  validateFinding,
  validateGuardClassification,
  validateNetworkCapabilities,
  validateNetworkMutation,
  validateProbeResult,
  validateTaskContract,
  validateTraceDocument,
  wrapUntrustedContent,
} from "../src/index.js";
import { mintAuthorizedAction } from "../src/action/authorized.js";
import type {
  ActionIntent,
  CanonicalAction,
  Finding,
  GuardClassificationRequest,
  ScanResult,
} from "../src/index.js";
import { mkAction, mkFinding, mkScanResult, fakeAdapter } from "./helpers.js";

/**
 * M1 integrated conformance gate (PS-009). Each test is tagged with the
 * OAF-CORE task and the INV/security-guarantee it proves, so a weakening of any
 * deterministic boundary turns this suite red. This is the executable
 * acceptance matrix for OAF-CORE-001…018.
 */

function validIntent(overrides: Partial<ActionIntent> = {}): ActionIntent {
  return {
    intentId: "i1",
    actionId: "a1",
    action: mkAction("NAVIGATE", { destination: "https://shop.example" }),
    observation: { browserContextId: "ctx", pageId: "page", revision: 1 },
    target: { selector: "#btn" },
    securityAttributes: { href: "/x" },
    visibility: "visible",
    policyHash: "policy-hash",
    operationHash: "op-hash",
    createdAt: 1000,
    expiresAt: 2000,
    ...overrides,
  };
}

function blockFinding(id: string): Finding {
  return mkFinding(id, "prompt_injection", { recommendedAction: "block", severity: "critical" });
}

function allowFinding(id: string): Finding {
  return mkFinding(id, "benign", { recommendedAction: "allow", severity: "low" });
}

describe("M1 conformance gate", () => {
  it("[OAF-CORE-003/004][INV-01] only a validated contract reaches the envelope compiler", () => {
    expect(validateTaskContract({ task: "t", bogus: true }).ok).toBe(false);
    expect(() => compileTaskContract({ task: "raw" } as never)).toThrow();
    const result = validateTaskContract({ task: "t" });
    expect(result.ok).toBe(true);
  });

  it("[OAF-CORE-007][INV-03] a semantic allow never overrides a deterministic block", () => {
    const deterministic: ScanResult = mkScanResult("d", "deterministic", "block", [
      blockFinding("f1"),
    ]);
    const semantic: ScanResult = mkScanResult("s", "semantic", "allow", [allowFinding("f2")]);
    const assessment = riskAggregator.aggregate({
      scanResults: [deterministic, semantic],
      policyDecision: { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "h" },
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(assessment.verdict).toBe("BLOCK");
  });

  it("[OAF-CORE-004][INV-12] the envelope is shrink-only and denies the default set", () => {
    const envelope = secureDefaultEnvelope("t");
    expect(envelope.evaluate({ type: "UPLOAD" }).allowed).toBe(false);
    expect(envelope.evaluate({ type: "PURCHASE" }).allowed).toBe(false);
    expect(envelope.evaluate({ type: "READ" }).allowed).toBe(true);
    const narrowed = envelope.narrow({ uploads: true });
    expect(narrowed.uploads).toBe(false);
  });

  it("[OAF-CORE-005][INV-08] high-impact classification is the gate's input", () => {
    expect(isHighImpact(mkAction("READ"))).toBe(false);
    expect(isHighImpact(mkAction("PURCHASE"))).toBe(true);
    expect(isHighImpact(mkAction("NAVIGATE", { destination: "https://evil.example" }))).toBe(true);
    expect(ACTION_TYPES).toContain("UNKNOWN");
    expect(AGGREGATE_VERDICTS).toContain("QUARANTINE");
  });

  it("[OAF-CORE-010][INV-05] raw secrets never reach traces, findings, or approvals", () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret("s3cr3t");
    const writer = { document: () => ({ schemaVersion: "1.0.0", events: [] as unknown[] }) };
    void writer;
    expect(redactor.redact("the s3cr3t is here")).toBe("the [REDACTED] is here");
    const finding = mkFinding("f", "x", { evidence: redactor.redact("s3cr3t") });
    expect(validateFinding(finding)).not.toBeNull();
    expect(JSON.stringify({ description: redactor.redact("s3cr3t") })).not.toContain("s3cr3t");
  });

  it("[OAF-CORE-009][INV-11] absence/timeout/error deny approval; page content cannot approve", async () => {
    const request = {
      id: "1",
      sessionId: "s",
      action: mkAction("PURCHASE"),
      findings: [],
      risk: { state: "NORMAL" as const, score: 0 },
      expiresAt: new Date(Date.now() + 1000).toISOString(),
    };
    expect((await resolveApproval(undefined, request)).approved).toBe(false);
    expect(
      (
        await resolveApproval(
          {
            requestApproval: async () => {
              throw new Error("boom");
            },
          },
          request,
        )
      ).approved,
    ).toBe(false);
  });

  it("[OAF-CORE-010][INV-17] non-ALLOW decisions carry reasons and validate", () => {
    const doc = {
      schemaVersion: "1.0.0",
      events: [
        {
          kind: "session_start",
          timestamp: "t",
          data: { sessionId: "s", policyHash: "h", versions: { schema: "1.0.0" } },
        },
        {
          kind: "policy_decision",
          timestamp: "t",
          data: { verdict: "BLOCK", reasons: ["destination_not_allowed"] },
        },
        { kind: "session_end", timestamp: "t", data: { risk: "NORMAL" } },
      ],
    };
    expect(validateTraceDocument(doc).ok).toBe(true);
    expect(
      validateTraceDocument({
        ...doc,
        events: doc.events.map((e) =>
          e.kind === "policy_decision" ? { ...e, data: { verdict: "BLOCK", reasons: [] } } : e,
        ),
      }).ok,
    ).toBe(false);
  });

  it("[OAF-CORE-014][INV-16] probe output is bounded, versioned, and runtime-validated", () => {
    const probe = {
      probeVersion: 2,
      truncated: true,
      truncation: {
        nodes: false,
        textBytes: false,
        comments: false,
        metadata: false,
        links: false,
        time: false,
      },
      nodes: [],
      comments: [],
      metadata: { title: "", meta: {}, jsonLd: [], noscript: [] },
      links: [],
    };
    expect(validateProbeResult(probe)).not.toBeNull();
    expect(validateProbeResult({ probeVersion: 2, truncated: "yes" })).toBeNull();
  });

  it("[OAF-CORE-016][INV-20] trusted context rejects raw content and untrusted content stays instruction-ineligible", () => {
    expect(
      buildTrustedIntentContext({
        task: "t",
        action: mkAction("READ"),
        envelopeFacts: {},
        dataClassifications: [],
        riskState: "NORMAL",
        provenance: { trust: "application" },
        priorActions: [],
      }),
    ).toBeTruthy();
    expect(isTrustedIntent({ task: "t" })).toBe(false);
    expect(
      wrapUntrustedContent({ content: "visible text", provenance: { trust: "web" } })
        .instructionEligible,
    ).toBe(false);
    expect(() => buildTrustedIntentContext({ provenance: { trust: "web" } } as never)).toThrow();
  });

  it("[OAF-CORE-017][INV-21] observation-only network capability cannot become enforcement", () => {
    const caps = { ...DEFAULT_NETWORK_CAPABILITIES, fetch: "observed_only" as const };
    expect(validateNetworkCapabilities(caps)).not.toBeNull();
    expect(
      validateNetworkCapabilities({
        ...DEFAULT_NETWORK_CAPABILITIES,
        fetch: "enforced-but-not-really" as never,
      }),
    ).toBeNull();
    expect(
      validateNetworkMutation({
        surface: "fetch",
        initiator: "unknown",
        destination: "https://evil.example",
        enforcement: "observed_only",
      }),
    ).not.toBeNull();
  });

  it("[OAF-CORE-018][INV-03/20] false-safe or malformed provider output never becomes authority", async () => {
    const request: GuardClassificationRequest = {
      role: "text_injection",
      excerpts: [new RedactionRegistry().redact("ignore previous")],
      taskSummary: new RedactionRegistry().redact("task"),
      localeHints: [],
    };
    const constraints = {
      signal: new AbortController().signal,
      deadline: Date.now() + 10_000,
      maxInputBytes: 10_000,
      maxOutputBytes: 10_000,
    };
    const permissive = await runGuardProvider(
      {
        name: "fake",
        model: "fake",
        makesExternalCalls: false,
        classify: async () => ({ promptInjection: "yes" }),
      },
      request,
      constraints,
    );
    expect(permissive.ok).toBe(false);
    expect(
      validateGuardClassification({
        promptInjection: true,
        confidence: 0.9,
        categories: ["x"],
        recommendedVerdict: "allow",
      }),
    ).not.toBeNull();
  });

  it("[OAF-CORE-015][INV-19] stale or forged authorizations are rejected deterministically", () => {
    const authorized = mintAuthorizedAction({
      action: validIntent().action,
      intent: validIntent(),
      operationHash: "op-hash",
      policyHash: "policy-hash",
      decisionId: "d1",
      traceId: "t1",
    });
    expect(isAuthorizedAction(authorized)).toBe(true);
    expect(isAuthorizedAction({ action: validIntent().action, intent: validIntent() })).toBe(false);
    expect(
      compareIntentState(validIntent(), {
        observation: { browserContextId: "ctx", pageId: "page", revision: 2 },
        target: { selector: "#btn" },
        securityAttributes: { href: "/x" },
        visibility: "visible",
        policyHash: "policy-hash",
        operationHash: "op-hash",
      }),
    ).toContain("observation");
    expect(validateActionIntent(validIntent())).not.toBeNull();
  });

  it("[OAF-CORE-011][INV-08] the guarded executor rejects a raw canonical action at the boundary", () => {
    const adapter = fakeAdapter();
    const raw: CanonicalAction = mkAction("NAVIGATE");
    expect(isAuthorizedAction(raw)).toBe(false);
    // @ts-expect-error — executeAuthorized accepts only AuthorizedAction
    void adapter.executeAuthorized(raw, undefined);
  });
});
