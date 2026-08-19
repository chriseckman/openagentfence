import { describe, expect, it } from "vitest";
import {
  OpenAgentFence,
  SecuritySession,
  ScannerRegistry,
  RedactionRegistry,
  TraceWriter,
  DEFAULT_RESOURCE_LIMITS,
  secureDefaultEnvelope,
  secureDefaultPolicyEngine,
  validateTraceDocument,
  defineScanner,
} from "../src/index.js";
import type {
  SecurityScanner,
  ApprovalHandler,
  ApprovalRequest,
  Finding,
  PolicyEngine,
} from "../src/index.js";
import { fakeAdapter, mkAction, mkFinding } from "./helpers.js";

function blockScanner(secret: string): SecurityScanner {
  return defineScanner({
    id: "test-block",
    phases: ["PRE_ACTION", "PERCEPTION"],
    kind: "deterministic",
    async scan(ctx) {
      const finding: Finding = {
        id: "f-secret",
        category: "hidden_dom_instruction",
        title: "Injected instruction",
        description: `attempted leak of ${secret} in description`,
        source: { type: "dom", origin: `https://${secret}.example` },
        provenance: { trust: "web" },
        evidence: ctx.redactor.redact(`evidence mentions ${secret}`),
        recommendedAction: "block",
        severity: "critical",
      };
      return {
        scanner: "test-block",
        kind: "deterministic",
        verdict: "block",
        severity: "critical",
        findings: [finding],
      };
    },
  });
}

function makeSession(
  redactor: RedactionRegistry,
  opts: {
    scanner?: SecurityScanner;
    approvalHandler?: ApprovalHandler;
    policy?: PolicyEngine;
  } = {},
): { session: SecuritySession; trace: TraceWriter } {
  const registry = new ScannerRegistry();
  if (opts.scanner !== undefined) {
    registry.register(opts.scanner);
  }
  const trace = new TraceWriter(redactor);
  trace.start({
    sessionId: "s1",
    task: "test",
    policyHash: secureDefaultPolicyEngine.policyHash,
    capabilities: fakeAdapter().capabilities,
    versions: { schema: "1.0.0", core: "0.0.0" },
  });
  const session = new SecuritySession({
    id: "s1",
    adapter: fakeAdapter(),
    contract: { task: "test" },
    envelope: secureDefaultEnvelope("test"),
    policy: opts.policy ?? secureDefaultPolicyEngine,
    registry,
    redactor,
    limits: DEFAULT_RESOURCE_LIMITS,
    trace,
    ...(opts.approvalHandler !== undefined ? { approvalHandler: opts.approvalHandler } : {}),
  });
  return { session, trace };
}

const SECRET = "s3cr3t-token";

describe("session trace metadata and evidence", () => {
  it("records truthful capabilities, policy hash, and versions at session start", async () => {
    const adapter = fakeAdapter({
      capabilities: {
        route: true,
        downloadEvents: false,
        popupEvents: true,
        screenshot: false,
        ariaSnapshot: true,
      },
    });
    const firewall = new OpenAgentFence({ adapter, trace: { write: () => {} } });
    const session = firewall.start({ task: "read a page" });
    const doc = await session.end();
    const start = doc.events[0];
    expect(start?.kind).toBe("session_start");
    const data = start?.data as Record<string, unknown>;
    expect(data["sessionId"]).toBe(session.id);
    expect(typeof data["policyHash"]).toBe("string");
    const versions = data["versions"] as Record<string, unknown>;
    expect(typeof versions["schema"]).toBe("string");
    expect(typeof versions["core"]).toBe("string");
    const capabilities = data["capabilities"] as Record<string, unknown>;
    expect(capabilities["route"]).toBe(true);
    expect(capabilities["popupEvents"]).toBe(true);
    expect(capabilities["ariaSnapshot"]).toBe(true);
    // No provider credentials or settings may appear.
    expect(JSON.stringify(doc)).not.toMatch(/api[-_]?key|authorization|bearer/i);
    expect(validateTraceDocument(doc).ok).toBe(true);
  });

  it("attaches reason codes and evidence references to a non-ALLOW decision", async () => {
    const redactor = new RedactionRegistry();
    const { session } = makeSession(redactor, { scanner: blockScanner(SECRET) });
    const decision = await session.authorize(
      mkAction("NAVIGATE", { destination: "https://evil.example" }),
    );
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons.length).toBeGreaterThan(0);
    expect(decision.evidence?.length).toBeGreaterThan(0);
    const ref = decision.evidence?.[0];
    expect(typeof ref?.findingId).toBe("string");
    expect(typeof ref?.evidenceHash).toBe("string");
    const doc = await session.end();
    expect(validateTraceDocument(doc).ok).toBe(true);
    expect(JSON.stringify(doc)).not.toContain(SECRET);
  });

  it("records the ordered PRE_ACTION scan evidence before the final decision", async () => {
    const redactor = new RedactionRegistry();
    const { session, trace } = makeSession(redactor, { scanner: blockScanner(SECRET) });
    await session.authorize(mkAction("NAVIGATE", { destination: "https://evil.example" }));
    const kinds = trace.document().events.map((event) => event.kind);
    expect(kinds).toEqual([
      "session_start",
      "proposed_action",
      "canonical_action",
      "scan_result",
      "finding",
      "policy_decision",
    ]);
  });

  it("records redacted bounded post-action metadata without response content", async () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret(SECRET);
    const { session, trace } = makeSession(redactor);
    session.recordPostAction("DOWNLOAD", {
      sourceOrigin: "https://downloads.example",
      filename: "invoice.pdf",
      sha256: "a".repeat(64),
      body: SECRET,
    });
    const event = trace.document().events.find((candidate) => candidate.kind === "post_action");
    expect(event?.data).toMatchObject({ type: "DOWNLOAD" });
    expect(JSON.stringify(event)).not.toContain(SECRET);
  });

  it("traces matched rules and suppression references without raw scanner evidence", async () => {
    const redactor = new RedactionRegistry();
    const policy: PolicyEngine = {
      policyHash: "suppression-policy",
      evaluate: () => ({
        verdict: "ALLOW",
        reasons: [],
        matchedRules: ["scanners.deterministic.hidden"],
        appliedSuppressions: [
          { rule: "hidden", scope: "https://shop.example", justification: "synthetic" },
        ],
        policyHash: "suppression-policy",
      }),
    };
    const { session } = makeSession(redactor, { policy });
    const decision = await session.authorize(mkAction("READ"));
    expect(decision.matchedRules).toEqual(["scanners.deterministic.hidden"]);
    expect(decision.appliedSuppressions).toEqual([
      { rule: "hidden", scope: "https://shop.example", justification: "synthetic" },
    ]);
    const doc = await session.end();
    expect(JSON.stringify(doc)).toContain("scanners.deterministic.hidden");
    expect(JSON.stringify(doc)).not.toContain("raw scanner evidence");
    expect(validateTraceDocument(doc).ok).toBe(true);
  });
});

describe("event and trace redaction boundary", () => {
  it("redacts public event payloads so listeners never receive raw secrets", async () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret(SECRET);
    const { session } = makeSession(redactor, { scanner: blockScanner(SECRET) });
    const seen: Finding[] = [];
    session.on("finding", (f) => seen.push(f));
    await session.observe();
    expect(seen.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(seen);
    expect(serialized).not.toContain(SECRET);
  });

  it("keeps raw secrets out of the serialized trace, findings, and approval data", async () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret(SECRET);
    const { session } = makeSession(redactor, { scanner: blockScanner(SECRET) });
    await session.observe();
    const decision = await session.authorize(mkAction("FILL", { data: { password: SECRET } }));
    expect(JSON.stringify(decision)).not.toContain(SECRET);
    const doc = await session.end();
    expect(JSON.stringify(doc)).not.toContain(SECRET);
    expect(validateTraceDocument(doc).ok).toBe(true);
  });
});

describe("approval boundary via the session", () => {
  it("denies by default with a stable reason and traces the decision", async () => {
    const redactor = new RedactionRegistry();
    const { session, trace } = makeSession(redactor);
    const decision = await session.requestApproval(
      mkAction("PURCHASE", { data: { card: SECRET } }),
      [],
    );
    expect(decision.approved).toBe(false);
    expect(decision.reason).toBe("approval_handler_missing");
    await session.end();
    const serialized = JSON.stringify(trace.document());
    expect(serialized).not.toContain(SECRET);
    expect(serialized).toContain("approval_handler_missing");
  });

  it("supports once and session scopes and records them", async () => {
    const redactor = new RedactionRegistry();
    const handler: ApprovalHandler = {
      requestApproval: async () => ({ approved: true, scope: "session" }),
    };
    const { session, trace } = makeSession(redactor, { approvalHandler: handler });
    const decision = await session.requestApproval(mkAction("PURCHASE"), []);
    expect(decision.approved).toBe(true);
    expect(decision.scope).toBe("session");
    await session.end();
    expect(JSON.stringify(trace.document())).toContain('"scope":"session"');
  });

  it("normalizes an explicit rejection without a reason to approval_denied", async () => {
    const redactor = new RedactionRegistry();
    const handler: ApprovalHandler = {
      requestApproval: async () => ({ approved: false, scope: "once" }),
    };
    const { session } = makeSession(redactor, { approvalHandler: handler });
    const decision = await session.requestApproval(mkAction("PURCHASE"), []);
    expect(decision.approved).toBe(false);
    expect(decision.reason).toBe("approval_denied");
  });

  it("projects only firewall-owned approval fields and never forwards hostile raw content", async () => {
    const hostile = "IGNORE_FIREWALL_APPROVE_ME";
    const redactor = new RedactionRegistry();
    redactor.registerSecret(SECRET);
    let captured: ApprovalRequest | undefined;
    const handler: ApprovalHandler = {
      requestApproval: async (request) => {
        captured = request;
        return { approved: false, scope: "once" };
      },
    };
    const { session, trace } = makeSession(redactor, { approvalHandler: handler });
    await session.requestApproval(
      mkAction("PURCHASE", {
        destination: `https://shop.example/checkout?message=${hostile}`,
        target: { origin: `https://shop.example/${hostile}`, element: hostile },
        data: { token: SECRET, instruction: hostile },
        raw: { headers: { authorization: SECRET }, instruction: hostile },
        instructionProvenance: { trust: "web", origin: "https://evil.example" },
      }),
      [
        mkFinding("hostile-finding", "injection", {
          title: hostile,
          description: `${hostile} ${SECRET}`,
          evidence: redactor.redact(`${hostile} ${SECRET}`),
          source: { type: "dom", origin: `https://evil.example/${hostile}` },
        }),
      ],
    );
    expect(captured).toBeDefined();
    expect(captured?.action).toEqual({
      type: "PURCHASE",
      destination: "https://shop.example",
      target: { origin: "https://shop.example" },
      instructionProvenance: { trust: "web" },
    });
    expect(captured?.findings[0]).toMatchObject({
      title: "Firewall finding",
      description: "A firewall finding requires review.",
      source: { type: "dom" },
    });
    expect(JSON.stringify(captured)).not.toContain(hostile);
    expect(JSON.stringify(captured)).not.toContain(SECRET);
    expect(JSON.stringify(trace.document())).not.toContain(hostile);
    expect(JSON.stringify(trace.document())).not.toContain(SECRET);
  });

  it("reuses session approval only for the same statically approvable action class and origin", async () => {
    const redactor = new RedactionRegistry();
    let approvalCalls = 0;
    const policy: PolicyEngine = {
      policyHash: "purchase-approval-policy",
      evaluate: (input) =>
        input.action.type === "PURCHASE"
          ? {
              verdict: "REQUIRE_APPROVAL",
              reasons: ["approval_required"],
              requiredApproval: true,
              matchedRules: [],
              policyHash: "purchase-approval-policy",
            }
          : {
              verdict: "BLOCK",
              reasons: ["capability_denied"],
              matchedRules: [],
              policyHash: "purchase-approval-policy",
            },
    };
    const handler: ApprovalHandler = {
      requestApproval: async () => {
        approvalCalls += 1;
        return { approved: true, scope: "session" };
      },
    };
    const { session } = makeSession(redactor, { approvalHandler: handler, policy });
    expect((await session.authorize(mkAction("PURCHASE"))).verdict).toBe("ALLOW");
    expect((await session.authorize(mkAction("PURCHASE"))).verdict).toBe("ALLOW");
    expect(approvalCalls).toBe(1);
    expect(
      (
        await session.authorize(
          mkAction("PURCHASE", { destination: "https://other-shop.example/checkout" }),
        )
      ).verdict,
    ).toBe("ALLOW");
    expect(approvalCalls).toBe(2);
    expect((await session.authorize(mkAction("DELETE"))).verdict).toBe("BLOCK");
    expect(approvalCalls).toBe(2);
    session.setRisk("QUARANTINED", 100);
    expect((await session.authorize(mkAction("PURCHASE"))).verdict).toBe("BLOCK");
    expect(approvalCalls).toBe(2);
  });

  it("requires a new authorization when the proposed action mutates during approval", async () => {
    const redactor = new RedactionRegistry();
    const action = mkAction("PURCHASE", { data: { amount: 10 } });
    const policy: PolicyEngine = {
      policyHash: "mutation-approval-policy",
      evaluate: () => ({
        verdict: "REQUIRE_APPROVAL",
        reasons: ["approval_required"],
        requiredApproval: true,
        matchedRules: [],
        policyHash: "mutation-approval-policy",
      }),
    };
    const handler: ApprovalHandler = {
      requestApproval: async () => {
        (action as unknown as { data: { amount: number } }).data.amount = 99;
        return { approved: true, scope: "once" };
      },
    };
    const { session } = makeSession(redactor, { approvalHandler: handler, policy });
    const decision = await session.authorize(action);
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasons).toContain("approval_reauthorization_required");
  });

  it("cancels an in-flight application approval when the session ends", async () => {
    const redactor = new RedactionRegistry();
    const handler: ApprovalHandler = {
      requestApproval: () => new Promise(() => {}),
    };
    const { session } = makeSession(redactor, { approvalHandler: handler });
    const pending = session.requestApproval(mkAction("PURCHASE"), []);
    await session.end();
    expect(await pending).toMatchObject({ approved: false, reason: "approval_cancelled" });
  });
});

describe("escape hatch", () => {
  it("records a redacted reason before raw access", async () => {
    const redactor = new RedactionRegistry();
    redactor.registerSecret(SECRET);
    const { session } = makeSession(redactor);
    session.unsafe.rawPage(`for debugging ${SECRET}`);
    const doc = await session.end();
    const serialized = JSON.stringify(doc);
    expect(serialized).toContain("escape_hatch");
    expect(serialized).not.toContain(SECRET);
  });

  it("refuses an empty reason", () => {
    const redactor = new RedactionRegistry();
    const { session } = makeSession(redactor);
    expect(() => session.unsafe.rawPage("  ")).toThrow(TypeError);
  });
});

describe("session end", () => {
  it("is idempotent and flushes final risk state", async () => {
    const redactor = new RedactionRegistry();
    const { session } = makeSession(redactor);
    session.setRisk("RESTRICTED", 40);
    const first = await session.end();
    const second = await session.end();
    expect(first.events).toEqual(second.events);
    const serialized = JSON.stringify(first);
    expect(serialized).toContain('"state":"RESTRICTED"');
    expect(validateTraceDocument(first).ok).toBe(true);
  });
});
