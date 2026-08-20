import { describe, expect, it } from "vitest";
import {
  OpenAgentFence,
  ScannerRegistry,
  applySanitizations,
  defineScanner,
  denyAllResolver,
  isCrossOrigin,
  isHighImpact,
  isPrivateNetworkDestination,
  mintHandle,
  originOf,
  sameOrigin,
  sameSite,
  hostnameOf,
  secureDefaultPolicyEngine,
  secureDefaultEnvelope,
  unknownActionNormalizer,
  riskAggregator,
  RedactionRegistry,
  REASON_CODES,
  buildScopedView,
  emptyPolicyRuntimeState,
  hash,
} from "../src/index.js";
import type {
  GuardModelProvider,
  VaultAdapter,
  ApprovalHandler,
  AdapterEventSink,
  NetworkMutation,
  PolicyDecision,
  PolicyEngine,
} from "../src/index.js";
import { fakeAdapter, mkAction, mkContext, mkFinding, mkScanResult } from "./helpers.js";

describe("secret scanner vault handoff", () => {
  it("materializes safe scanner markers as handles without releasing the matched value", async () => {
    const secret = "syntheticPassword123";
    let stored: string | undefined;
    const vault: VaultAdapter = {
      openSession: () => ({
        store: async (name, value, kind = "SECRET") => {
          stored = value;
          return { name, kind, id: "a".repeat(32) };
        },
        createExecutorLookup: () => ({ lookup: async () => null }),
        invalidateSession: async () => {},
      }),
    };
    const scanner = defineScanner({
      id: "synthetic-secret",
      phases: ["PERCEPTION"],
      kind: "deterministic",
      scan: async (ctx) => ({
        scanner: "synthetic-secret",
        kind: "deterministic",
        verdict: "sanitize",
        severity: "high",
        findings: [],
        sanitizations: [
          {
            start: 0,
            end: secret.length,
            replacement: "[[OAF_SENSITIVE:CREDENTIAL:password]]",
            provenance: ctx.provenance,
          },
        ],
      }),
    });
    const session = new OpenAgentFence({
      adapter: fakeAdapter({
        observe: async () => ({
          url: "https://example.com",
          origin: "https://example.com",
          frames: [],
          ariaSnapshot: secret,
          provenance: { trust: "web", timestamp: new Date().toISOString() },
        }),
      }),
      scanners: [scanner],
      vault,
    }).start({ task: "test" });
    const result = await session.observe();
    expect(stored).toBe(secret);
    expect(result.sanitizedText.value).toBe(
      `<CREDENTIAL:detected_password_${hash(secret).slice(0, 8)}:${"a".repeat(32)}>`,
    );
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(await session.end())).not.toContain(secret);
  });
});

function allow(overrides: Partial<PolicyDecision> = {}): PolicyDecision {
  return { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "h", ...overrides };
}

describe("action classification", () => {
  it("treats anything outside READ/SCROLL as high impact", () => {
    expect(isHighImpact(mkAction("READ"))).toBe(false);
    expect(isHighImpact(mkAction("SCROLL"))).toBe(false);
    expect(isHighImpact(mkAction("SUBMIT"))).toBe(true);
    expect(isHighImpact(mkAction("NAVIGATE"))).toBe(true);
  });

  it("treats side-effect classes above REVERSIBLE as high impact", () => {
    expect(isHighImpact(mkAction("READ", { sideEffectClass: "FINANCIAL" }))).toBe(true);
    expect(isHighImpact(mkAction("READ", { sideEffectClass: "REVERSIBLE" }))).toBe(false);
  });

  it("treats a secret handle in data as high impact", () => {
    expect(
      isHighImpact(mkAction("READ", { data: "<SECRET:x:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa>" })),
    ).toBe(true);
  });

  it("detects cross-origin destinations", () => {
    expect(
      isCrossOrigin(
        mkAction("NAVIGATE", {
          destination: "https://evil.example",
          target: { origin: "https://good.example" },
        }),
      ),
    ).toBe(true);
    expect(
      isCrossOrigin(
        mkAction("NAVIGATE", {
          destination: "https://good.example/x",
          target: { origin: "https://good.example" },
        }),
      ),
    ).toBe(false);
    expect(isCrossOrigin(mkAction("READ"))).toBe(false);
    expect(isCrossOrigin(mkAction("NAVIGATE", { destination: "https://x.example" }))).toBe(true);
  });
});

describe("url normalization", () => {
  it("extracts origins and hostnames", () => {
    expect(originOf("https://example.com/a/b")).toBe("https://example.com");
    expect(hostnameOf("https://example.com:8080/x")).toBe("example.com");
    expect(originOf("not a url")).toBeNull();
    expect(hostnameOf("not a url")).toBeNull();
  });

  it("compares origins and sites", () => {
    expect(sameOrigin("https://a.example", "https://a.example/x")).toBe(true);
    expect(sameOrigin("https://a.example", "https://b.example")).toBe(false);
    expect(sameSite("https://a.example.com", "https://b.example.com")).toBe(true);
    expect(sameSite("https://a.example.com", "https://b.other.com")).toBe(false);
  });
});

describe("private network detection", () => {
  const blocked = [
    "http://127.0.0.1",
    "http://localhost",
    "http://10.0.0.5",
    "http://172.16.0.1",
    "http://172.31.255.255",
    "http://192.168.1.1",
    "http://169.254.169.254",
    "http://metadata.google.internal",
    "http://[::1]",
    "http://[fd00::1]",
  ];
  const allowed = [
    "http://example.com",
    "http://8.8.8.8",
    "http://172.32.0.1",
    "http://[2001:db8::1]",
    "not a url",
  ];
  it("blocks private and metadata destinations", () => {
    for (const url of blocked) {
      expect(isPrivateNetworkDestination(url), url).toBe(true);
    }
  });
  it("allows public destinations", () => {
    for (const url of allowed) {
      expect(isPrivateNetworkDestination(url), url).toBe(false);
    }
  });
});

describe("sanitization and normalizer", () => {
  it("applies sanitizations sequentially", () => {
    expect(
      applySanitizations("base", [
        { value: "first", provenance: { trust: "web" } },
        { value: "second", provenance: { trust: "web" } },
      ]),
    ).toBe("second");
    expect(applySanitizations("base", [])).toBe("base");
  });

  it("normalizes unknown operations conservatively", () => {
    expect(unknownActionNormalizer({ foo: "bar" }).type).toBe("UNKNOWN");
  });
});

describe("scanner registry", () => {
  it("registers, lists sorted, and rejects duplicates", () => {
    const r = new ScannerRegistry();
    const s = defineScanner({
      id: "a",
      phases: ["PERCEPTION"],
      kind: "semantic",
      scan: async () => ({
        scanner: "a",
        kind: "semantic" as const,
        verdict: "allow" as const,
        severity: "low" as const,
        findings: [],
      }),
    });
    r.register(s);
    expect(r.get("a")).toBe(s);
    expect(r.list("PERCEPTION")).toHaveLength(1);
    expect(r.list("PRE_ACTION")).toHaveLength(0);
    expect(() => r.register(s)).toThrow();
    r.clear();
    expect(r.get("a")).toBeUndefined();
  });

  it("rejects invalid defineScanner input", () => {
    expect(() =>
      defineScanner({
        id: " ",
        phases: ["PERCEPTION"],
        kind: "deterministic",
        scan: async () => ({
          scanner: "x",
          kind: "deterministic" as const,
          verdict: "allow" as const,
          severity: "low" as const,
          findings: [],
        }),
      }),
    ).toThrow();
    expect(() =>
      defineScanner({
        id: "x",
        phases: ["BOGUS" as never],
        kind: "deterministic",
        scan: async () => ({
          scanner: "x",
          kind: "deterministic" as const,
          verdict: "allow" as const,
          severity: "low" as const,
          findings: [],
        }),
      }),
    ).toThrow();
  });
});

describe("secret resolver stub", () => {
  it("always denies", async () => {
    const handle = mintHandle("SECRET", "k");
    expect(
      await denyAllResolver.resolveForSink(handle, { origin: "https://a", fieldType: "password" }),
    ).toBeNull();
  });
});

describe("secure default engine quarantine", () => {
  it("blocks quarantined sessions", () => {
    const d = secureDefaultPolicyEngine.evaluate({
      action: { type: "READ", instructionProvenance: { trust: "application" } },
      envelope: secureDefaultEnvelope("t"),
      riskState: "QUARANTINED",
      runtimeState: emptyPolicyRuntimeState,
    });
    expect(d.verdict).toBe("BLOCK");
    expect(d.reasons).toContain(REASON_CODES.session_restricted);
  });
});

describe("session lifecycle", () => {
  it("emits risk changes and decisions, and unsubscribe works", () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "t" });
    const events: string[] = [];
    const off = session.on("riskChanged", () => events.push("risk"));
    session.setRisk("RESTRICTED", 50);
    expect(events).toEqual(["risk"]);
    off();
    session.setRisk("RESTRICTED", 50);
    expect(events).toEqual(["risk"]);
  });

  it("end() is idempotent", async () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "t" });
    const d1 = await session.end();
    const d2 = await session.end();
    expect(d1.events.length).toBe(d2.events.length);
  });

  it("allows only the ADR-0015 link navigation exception in READ_ONLY", async () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "t" });
    await session.observe();
    session.setRisk("READ_ONLY", 80);
    const [link] = await session.authorizeActions(
      [
        mkAction("NAVIGATE", {
          destination: "https://next.example.com/path",
          target: { origin: "https://example.com" },
          navigationOrigin: "link",
        }),
      ],
      { instructedBy: "user" },
    );
    const [direct] = await session.authorizeActions(
      [
        mkAction("NAVIGATE", {
          destination: "https://next.example.com/path",
          target: { origin: "https://example.com" },
          navigationOrigin: "direct",
        }),
      ],
      { instructedBy: "user" },
    );
    expect(link?.verdict).toBe("ALLOW");
    expect(direct?.verdict).toBe("BLOCK");
    expect(direct?.reasons).toContain(REASON_CODES.session_restricted);
  });

  it("makes restricted side effects require application approval and blocks secret typing", async () => {
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      approvalHandler: { requestApproval: async () => ({ approved: true, scope: "once" }) },
    });
    const session = firewall.start({ task: "t", capabilities: { purchases: true } });
    await session.observe();
    session.setRisk("RESTRICTED", 40);
    const sideEffect = await session.authorize(mkAction("PURCHASE"));
    const secretType = await session.authorize(
      mkAction("TYPE", {
        target: { origin: "https://example.com" },
        data: "<SECRET:x:abcdefabcdefabcdefabcdefabcdefab>",
      }),
    );
    expect(sideEffect.verdict).toBe("ALLOW");
    expect(secretType.verdict).toBe("BLOCK");
    expect(secretType.reasons).toContain(REASON_CODES.session_restricted);
  });

  it("merges a restricted cross-origin navigation block with a policy destination block", async () => {
    const policy: PolicyEngine = {
      policyHash: "destination-block-test",
      evaluate: () => ({
        verdict: "BLOCK",
        reasons: [REASON_CODES.destination_not_allowed],
        matchedRules: ["destination"],
        policyHash: "destination-block-test",
      }),
    };
    const firewall = new OpenAgentFence({ adapter: fakeAdapter(), policy });
    const session = firewall.start({ task: "t" });
    await session.observe();
    session.setRisk("RESTRICTED", 40);

    const [decision] = await session.authorizeActions(
      [mkAction("NAVIGATE", { destination: "https://evil.example/path" })],
      { instructedBy: "user" },
    );

    expect(decision?.verdict).toBe("BLOCK");
    expect(decision?.reasons).toEqual([
      REASON_CODES.destination_not_allowed,
      REASON_CODES.session_restricted,
    ]);
  });

  it("blocks an unbound handle before PRE_ACTION scanners run", async () => {
    let scans = 0;
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      scanners: [
        defineScanner({
          id: "pre-action-observer",
          phases: ["PRE_ACTION"],
          kind: "deterministic",
          scan: async () => {
            scans += 1;
            return {
              scanner: "pre-action-observer",
              kind: "deterministic",
              verdict: "allow",
              severity: "info",
              findings: [],
            };
          },
        }),
      ],
    });
    const session = firewall.start({ task: "t" });
    const decision = await session.authorize(
      mkAction("NAVIGATE", {
        destination: "https://example.com/?q=<SECRET:missing:deadbeefdeadbeefdeadbeefdeadbeef>",
      }),
    );
    expect(decision).toMatchObject({
      verdict: "BLOCK",
      reasons: [REASON_CODES.secret_sink_not_allowed],
    });
    expect(scans).toBe(0);
  });

  it("runs PRE_ACTION scanners before policy and retains both deterministic reasons", async () => {
    const calls: string[] = [];
    const policy: PolicyEngine = {
      policyHash: "ordered-policy",
      evaluate: () => {
        calls.push("policy");
        return {
          verdict: "BLOCK",
          reasons: [REASON_CODES.destination_not_allowed],
          matchedRules: ["destination"],
          policyHash: "ordered-policy",
        };
      },
    };
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      policy,
      scanners: [
        defineScanner({
          id: "required-pre-action",
          phases: ["PRE_ACTION"],
          kind: "deterministic",
          scan: async () => {
            calls.push("scanner");
            throw new Error("synthetic failure");
          },
        }),
      ],
    });
    const decision = await firewall.start({ task: "t" }).authorize(mkAction("NAVIGATE"));
    expect(calls).toEqual(["scanner", "policy"]);
    expect(decision).toMatchObject({
      verdict: "BLOCK",
      reasons: [REASON_CODES.destination_not_allowed, REASON_CODES.scanner_unavailable],
    });
  });

  it("never turns a deterministic policy block into approvable budget exhaustion", async () => {
    let approvals = 0;
    const policy: PolicyEngine = {
      policyHash: "final-block",
      evaluate: () => ({
        verdict: "BLOCK",
        reasons: [REASON_CODES.destination_not_allowed],
        matchedRules: ["destination"],
        policyHash: "final-block",
      }),
    };
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      policy,
      approvalHandler: {
        requestApproval: async () => {
          approvals += 1;
          return { approved: true, scope: "once" };
        },
      },
    });
    const decision = await firewall
      .start({ task: "t", budgets: { maxActions: 0 } })
      .authorize(mkAction("PURCHASE"));

    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons).toEqual([
      REASON_CODES.destination_not_allowed,
      REASON_CODES.budget_exceeded,
    ]);
    expect(approvals).toBe(0);
  });

  it("rejects an undeclared secret handle in raw adapter operation data before scanners", async () => {
    let scans = 0;
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      scanners: [
        defineScanner({
          id: "raw-handle-observer",
          phases: ["PRE_ACTION"],
          kind: "deterministic",
          scan: async () => {
            scans += 1;
            return {
              scanner: "raw-handle-observer",
              kind: "deterministic",
              verdict: "allow",
              severity: "info",
              findings: [],
            };
          },
        }),
      ],
    });
    const decision = await firewall.start({ task: "t" }).authorize(
      mkAction("CLICK", {
        raw: { headers: { authorization: "<SECRET:missing:deadbeefdeadbeefdeadbeefdeadbeef>" } },
      }),
    );

    expect(decision).toMatchObject({
      verdict: "BLOCK",
      reasons: [REASON_CODES.secret_sink_not_allowed],
    });
    expect(scans).toBe(0);
  });

  it("blocks an over-budget routed redirect before the adapter continues it", () => {
    let sink: AdapterEventSink | undefined;
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter({
        subscribe: (_sessionId, registeredSink) => {
          sink = registeredSink;
          return () => {};
        },
      }),
    });
    firewall.start({ task: "t", budgets: { maxRedirectHops: 0 } });
    const mutation: NetworkMutation = {
      surface: "redirect",
      initiator: "redirect",
      origin: "https://example.com",
      destination: "https://example.com/next",
      enforcement: "enforced",
      provenance: { trust: "web", timestamp: "2026-01-01T00:00:00.000Z" },
      redirectHops: 1,
    };

    expect(sink?.onRouteRequest?.(mutation)).toMatchObject({
      verdict: "block",
      reasons: [REASON_CODES.budget_exceeded],
      enforcement: "enforced",
    });
  });

  it("permits only explicit application quarantine release", async () => {
    const firewall = new OpenAgentFence({ adapter: fakeAdapter() });
    const session = firewall.start({ task: "t" });
    session.applyRiskSignal("critical_finding");
    expect(session.riskState).toBe("QUARANTINED");
    expect(session.releaseQuarantine()).toBe(true);
    expect(session.riskState).toBe("NORMAL");
    expect(session.releaseQuarantine()).toBe(false);
    const trace = await session.end();
    expect(JSON.stringify(trace)).toContain('"release":"application"');
  });
});

describe("aggregator remaining precedence", () => {
  it("semantic approve yields REQUIRE_APPROVAL", () => {
    const r = riskAggregator.aggregate({
      scanResults: [
        mkScanResult("sem", "semantic", "approve", [
          mkFinding("s", "injection", { recommendedAction: "approve" }),
        ]),
      ],
      policyDecision: allow(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("REQUIRE_APPROVAL");
  });

  it("budgets exhausted degrade ALLOW to WARN", () => {
    const r = riskAggregator.aggregate({
      scanResults: [],
      policyDecision: allow(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: true,
    });
    expect(r.verdict).toBe("WARN");
    expect(r.reasons).toContain(REASON_CODES.budget_exceeded);
  });

  it("sanitized output yields ALLOW_SANITIZED", () => {
    const r = riskAggregator.aggregate({
      scanResults: [
        mkScanResult("det", "deterministic", "sanitize", [], {
          sanitized: { value: "clean", provenance: { trust: "web" } },
        }),
      ],
      policyDecision: allow(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.verdict).toBe("ALLOW_SANITIZED");
  });

  it("buckets provenance findings", () => {
    const r = riskAggregator.aggregate({
      scanResults: [
        mkScanResult("det", "deterministic", "warn", [
          mkFinding("p", "instruction_provenance_untrusted", { recommendedAction: "warn" }),
        ]),
      ],
      policyDecision: allow(),
      riskState: "NORMAL",
      score: 0,
      budgetsExhausted: false,
    });
    expect(r.provenance.length).toBe(1);
  });
});

describe("redaction registry helpers", () => {
  it("tracks secrets and fingerprints, dedupes", () => {
    const r = new RedactionRegistry();
    r.registerSecret("abc");
    r.registerSecret("abc");
    expect(r.isSecret("abc")).toBe(true);
    expect(r.isSecret("def")).toBe(false);
    expect(r.secretFingerprints()).toHaveLength(1);
  });
});

describe("facade with full options", () => {
  it("uses a configured guard model, vault, and approval handler", async () => {
    const guardModel: GuardModelProvider = {
      name: "g",
      model: "m",
      makesExternalCalls: false,
      classify: async () => ({
        promptInjection: false,
        confidence: 0,
        categories: [],
        recommendedVerdict: "allow",
      }),
    };
    const vault: VaultAdapter = {
      openSession: () => ({
        store: async () => mintHandle("SECRET", "k"),
        createExecutorLookup: () => ({ lookup: async () => null }),
        invalidateSession: async () => {},
      }),
    };
    const approvalHandler: ApprovalHandler = {
      requestApproval: async () => ({ approved: true, scope: "once" }),
    };
    const firewall = new OpenAgentFence({
      adapter: fakeAdapter(),
      guardModel,
      vault,
      approvalHandler,
    });
    const session = firewall.start({
      task: "t",
      budgets: { maxGuardCalls: 1, maxGuardTokens: 4 },
    });
    expect(session.guardProvider).toBe(guardModel);
    const redactor = new RedactionRegistry();
    const guardOutcome = await session.classifyWithGuard(
      {
        role: "text_injection",
        excerpts: [redactor.redact("bounded excerpt")],
        taskSummary: redactor.redact("trusted task"),
        localeHints: ["en"],
        budget: { maxTokens: 4 },
      },
      { signal: new AbortController().signal, deadline: Date.now() + 1_000 },
    );
    expect(guardOutcome).toMatchObject({ ok: true });
    expect(
      await session.classifyWithGuard(
        {
          role: "text_injection",
          excerpts: [redactor.redact("second excerpt")],
          taskSummary: redactor.redact("trusted task"),
          localeHints: ["en"],
          budget: { maxTokens: 4 },
        },
        { signal: new AbortController().signal, deadline: Date.now() + 1_000 },
      ),
    ).toEqual({ ok: false, kind: "budget_exhausted" });
    const decision = await session.requestApproval(
      { type: "PURCHASE", instructionProvenance: { trust: "application" } },
      [],
    );
    expect(decision.approved).toBe(true);
  });
});

describe("scoped context view remaining branches", () => {
  it("includes screenshot with page:screenshot permission", () => {
    const ctx = mkContext("PERCEPTION", {
      kind: "observation",
      observation: {
        url: "https://x",
        origin: "https://x",
        frames: [],
        screenshot: "ref",
        provenance: { trust: "web" },
      },
    });
    const view = buildScopedView(ctx, ["page:screenshot"]);
    expect(view.observation?.["screenshot"]).toBe("ref");
    expect(view.observation?.["ariaSnapshot"]).toBeUndefined();
  });

  it("includes action data with action:data permission", () => {
    const ctx = mkContext("PRE_ACTION", {
      kind: "proposedAction",
      action: mkAction("FILL", { data: "hello" }),
    });
    const view = buildScopedView(ctx, ["action:data"]);
    expect(view.action?.["data"]).toEqual({ value: "hello", provenance: { trust: "application" } });
  });
});
