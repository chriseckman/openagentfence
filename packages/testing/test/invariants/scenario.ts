import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect } from "vitest";
import {
  DEFAULT_NETWORK_CAPABILITIES,
  OpenAgentFence,
  REASON_CODES,
  RedactionRegistry,
  ScannerRegistry,
  applySanitizationPipeline,
  compareIntentState,
  definePluginScanner,
  evaluateDestination,
  evaluateNetworkMutation,
  provenanced,
  redactDeep,
  resolveApproval,
  riskAggregator,
  runGuardProvider,
  runPhase,
  secureDefaultEnvelope,
  serializeHandle,
  type ActionIntent,
  type AdapterEventSink,
  type BrowserAdapter,
  type CanonicalAction,
  type DataProvenance,
  type Finding,
  type GuardModelProvider,
  type NetworkMutation,
  type ScanResult,
  type SecretHandle,
  type SessionVault,
  type VaultAdapter,
} from "@openagentfence/core";
import { decodeIterative, defaultScanners } from "@openagentfence/scanners";
import { expectNoRawSecretIn } from "../../src/assertions.js";
import { fixtureSentinel } from "../../src/fixture-server.js";
import { loadCorpusFile } from "../../src/corpus.js";
import {
  ATTACK_COVERAGE,
  GUARANTEE_COVERAGE,
  INVARIANT_COVERAGE,
  INVARIANT_IDS,
  attackCoverageErrors,
  type InvariantId,
} from "./coverage-registry.js";

const REPO_ROOT = resolve(import.meta.dirname, "../../../..");
const WEB_PROVENANCE: DataProvenance = Object.freeze({
  trust: "web",
  origin: "https://page.example",
  frameOrigin: "https://page.example",
  pageId: "page-1",
  elementId: "node-1",
  timestamp: "2026-08-20T00:00:00.000Z",
});

function fakeAdapter(overrides: Partial<BrowserAdapter> = {}): BrowserAdapter {
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
      url: "https://page.example",
      origin: "https://page.example",
      pageId: "page-1",
      frames: [],
      provenance: WEB_PROVENANCE,
    }),
    executeAuthorized: async () => undefined,
    subscribe: () => () => undefined,
    rawPage: () => ({ raw: true }),
    ...overrides,
  };
}

function action(
  type: CanonicalAction["type"],
  overrides: Omit<Partial<CanonicalAction>, "data"> & { readonly data?: unknown } = {},
): CanonicalAction {
  const { data, ...rest } = overrides;
  return {
    type,
    instructionProvenance: { trust: "application" },
    ...(data === undefined ? {} : { data: provenanced(data, { trust: "application" }) }),
    ...rest,
  };
}

function finding(
  id: string,
  recommendedAction: Finding["recommendedAction"],
  redactor: RedactionRegistry,
): Finding {
  return {
    id,
    category: id,
    title: id,
    description: id,
    source: { type: "tool" },
    provenance: WEB_PROVENANCE,
    evidence: redactor.redact(id),
    recommendedAction,
  };
}

function result(
  kind: ScanResult["kind"],
  item: Finding,
  verdict: ScanResult["verdict"],
): ScanResult {
  return {
    scanner: `${kind}-fixture`,
    kind,
    verdict,
    severity: "critical",
    findings: [item],
  };
}

function vaultAdapter(): VaultAdapter {
  return {
    openSession: (): SessionVault => {
      const entries = new Map<string, string>();
      return {
        store: async (name, value, kind = "SECRET") => {
          const handle = {
            kind,
            name,
            id: "abcdefabcdefabcdefabcdefabcdefab",
          } as const;
          entries.set(serializeHandle(handle), value);
          return handle;
        },
        createExecutorLookup: () => ({
          lookup: async (handle) => entries.get(serializeHandle(handle)) ?? null,
        }),
        invalidateSession: async () => entries.clear(),
      };
    },
  };
}

async function blockedHighImpact() {
  const session = new OpenAgentFence({ adapter: fakeAdapter() }).start({ task: "read only" });
  const decision = await session.authorize(action("PURCHASE"));
  const trace = await session.end();
  return { decision, trace };
}

async function exercise(id: InvariantId, sentinel: string): Promise<unknown> {
  switch (id) {
    case "INV-01": {
      const session = new OpenAgentFence({ adapter: fakeAdapter() }).start({ task: "read" });
      const before = session.envelope;
      const decision = await session.authorize(
        action("NAVIGATE", {
          destination: "https://attacker.example/",
          target: { origin: "https://page.example" },
          instructionProvenance: WEB_PROVENANCE,
        }),
      );
      expect(decision.verdict).toBe("BLOCK");
      expect(session.envelope).toBe(before);
      return session.end();
    }
    case "INV-02": {
      const corpus = loadCorpusFile(resolve(REPO_ROOT, "security-corpus/corpus.json"));
      const cases = new Map(corpus.cases.map((item) => [item.id, item]));
      expect(INVARIANT_COVERAGE.map((entry) => entry.id)).toEqual(INVARIANT_IDS);
      expect(new Set(INVARIANT_COVERAGE.map((entry) => entry.id)).size).toBe(21);
      const specFiles = readdirSync(resolve(import.meta.dirname), { withFileTypes: true })
        .filter((entry) => entry.isFile() && /^INV-\d{2}\.spec\.ts$/u.test(entry.name))
        .map((entry) => entry.name)
        .sort();
      expect(specFiles).toEqual(INVARIANT_IDS.map((item) => `${item}.spec.ts`));
      expect(ATTACK_COVERAGE.map((entry) => entry.id)).toEqual(
        Array.from({ length: 20 }, (_, index) => `A${index + 1}`),
      );
      const scanners = new Set(defaultScanners().map((scanner) => scanner.id));
      expect(attackCoverageErrors(ATTACK_COVERAGE, corpus.cases, scanners)).toEqual([]);
      expect(attackCoverageErrors(ATTACK_COVERAGE.slice(1), corpus.cases, scanners)).toContain(
        "attack-class-set",
      );
      for (const [index, attack] of ATTACK_COVERAGE.entries()) {
        expect(
          attackCoverageErrors(
            ATTACK_COVERAGE.map((entry, entryIndex) =>
              entryIndex === index ? { ...entry, deterministicControls: [] } : entry,
            ),
            corpus.cases,
            scanners,
          ),
        ).toContain(`${attack.id}:control-missing`);
        expect(
          attackCoverageErrors(
            ATTACK_COVERAGE,
            corpus.cases.filter((item) => !attack.corpusCaseIds.includes(item.id)),
            scanners,
          ),
        ).toContain(`${attack.id}:case-absent`);
      }
      for (const entry of INVARIANT_COVERAGE) {
        expect(entry.boundaries.length, entry.id).toBeGreaterThan(0);
        expect(entry.deterministicControls.length, entry.id).toBeGreaterThan(0);
        for (const caseId of entry.corpusCaseIds) {
          const item = cases.get(caseId);
          expect(item, `${entry.id}/${caseId}`).toBeDefined();
          expect(item?.invariants, caseId).toContain(entry.id);
        }
        for (const path of entry.evidenceFiles) {
          expect(readFileSync(resolve(REPO_ROOT, path), "utf8").length, path).toBeGreaterThan(0);
        }
      }
      expect(GUARANTEE_COVERAGE).toHaveLength(10);
      for (const row of GUARANTEE_COVERAGE) {
        expect(INVARIANT_IDS).toContain(row.invariant);
        const item = cases.get(row.corpusCaseId);
        expect(item, row.id).toBeDefined();
        expect(item?.invariants, row.id).toContain(row.invariant);
      }
      expect(expectNoRawSecretIn({ leaked: sentinel }, sentinel)).toBe(false);
      return { corpusHash: corpus.hash, attacks: ATTACK_COVERAGE.length };
    }
    case "INV-03": {
      const redactor = new RedactionRegistry();
      const assessment = riskAggregator.aggregate({
        scanResults: [
          result("deterministic", finding("deterministic-block", "block", redactor), "block"),
          result("semantic", finding("semantic-allow", "allow", redactor), "allow"),
        ],
        policyDecision: { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "p" },
        riskState: "NORMAL",
        score: 0,
        budgetsExhausted: false,
      });
      expect(assessment.verdict).toBe("BLOCK");
      expect(assessment.decidedBy?.layer).toBe("critical");
      return assessment;
    }
    case "INV-04": {
      let executions = 0;
      const handleRef: { current?: SecretHandle } = {};
      const session = new OpenAgentFence({
        adapter: fakeAdapter({
          executeAuthorized: async (_authorized, resolver) => {
            executions += 1;
            if (handleRef.current === undefined) throw new Error("secret handle unavailable");
            return resolver.resolveForSink(handleRef.current, {
              origin: "https://attacker.example",
              fieldType: "password",
              selector: "#password",
            });
          },
        }),
        vault: vaultAdapter(),
      }).start({
        task: "sign in",
        capabilities: { credentials: true },
        secrets: [
          {
            name: "login",
            kind: "CREDENTIAL",
            origins: ["https://safe.example"],
            fieldTypes: ["password"],
            selector: "#password",
          },
        ],
      });
      const handle = await session.registerSecret("login", sentinel, "CREDENTIAL");
      handleRef.current = handle;
      const serializedHandle = serializeHandle(handle);
      const fill = action("FILL", {
        target: { element: "#password", origin: "https://safe.example" },
        data: serializedHandle,
      });
      const now = Date.now();
      const intent: ActionIntent = {
        intentId: "secret-intent",
        actionId: "secret-action",
        action: fill,
        observation: { browserContextId: "ctx", pageId: "page-1", revision: 1 },
        target: {
          selector: "#password",
          element: "#password",
          origin: "https://safe.example",
        },
        securityAttributes: { type: "password" },
        visibility: "visible",
        policyHash: session.policyEngine.policyHash,
        operationHash: "fill-operation",
        createdAt: now,
        expiresAt: now + 60_000,
      };
      const bound = await session.authorizeBound(fill, intent);
      expect(bound.decision.verdict).toBe("ALLOW");
      if (bound.authorized === undefined) throw new Error("expected bound authorization");
      const resolved = await session.executeAuthorized(bound.authorized);
      expect(resolved).toBeNull();
      expect(executions).toBe(1);
      return { decision: bound.decision, resolved, trace: await session.end() };
    }
    case "INV-05": {
      const redactor = new RedactionRegistry();
      expect(redactor.registerSecret(sentinel)).toBe(true);
      const artifact = redactDeep(
        { event: sentinel, encoded: Buffer.from(sentinel).toString("base64") },
        redactor,
      );
      expect(expectNoRawSecretIn(artifact, sentinel)).toBe(true);
      return artifact;
    }
    case "INV-06": {
      const session = new OpenAgentFence({ adapter: fakeAdapter(), vault: vaultAdapter() }).start({
        task: "send approved data",
        capabilities: { messaging: true, externalCommunication: true },
        origins: { allow: ["https://safe.example", "https://attacker.example"] },
        secrets: [
          {
            name: "message",
            kind: "SECRET",
            origins: ["https://safe.example"],
            fieldTypes: ["message"],
          },
        ],
      });
      await session.registerSecret("message", sentinel);
      const decision = await session.authorize(
        action("MESSAGE", { destination: "https://attacker.example/send", data: sentinel }),
      );
      expect(decision.verdict).toBe("BLOCK");
      expect(decision.reasons).toContain(REASON_CODES.sensitive_value_in_egress);
      return { decision, trace: await session.end() };
    }
    case "INV-07": {
      const session = new OpenAgentFence({
        adapter: fakeAdapter(),
        scanners: defaultScanners(),
      }).start({ task: "remember" });
      const written = await session.memory.guardWrite({
        content: "Visible account status",
        provenance: WEB_PROVENANCE,
      });
      expect(written.allowed).toBe(true);
      if (written.item === undefined) throw new Error("memory guard omitted an allowed item");
      const released = session.memory.guardRead(written.item);
      expect(released.provenance.trust).toBe("memory");
      expect(released.provenance.origin).toBe(WEB_PROVENANCE.origin);
      expect(released.instructionEligible).toBe(false);
      return { written, released, trace: await session.end() };
    }
    case "INV-08": {
      const artifact = await blockedHighImpact();
      expect(artifact.decision.verdict).toBe("BLOCK");
      return artifact;
    }
    case "INV-09": {
      const required = {
        id: "required-failure",
        phases: ["PRE_ACTION"] as const,
        kind: "deterministic" as const,
        tier: "tier0" as const,
        priority: 0,
        scan: async () => {
          throw new Error("synthetic required failure");
        },
      };
      const session = new OpenAgentFence({ adapter: fakeAdapter(), scanners: [required] }).start({
        task: "purchase",
        capabilities: { purchases: true },
      });
      const decision = await session.authorize(action("PURCHASE"));
      expect(decision.verdict).toBe("BLOCK");
      expect(decision.reasons).toContain(REASON_CODES.scanner_unavailable);
      return { decision, trace: await session.end() };
    }
    case "INV-10": {
      const decision = evaluateDestination({
        destination: "http://127.0.0.1/admin",
        envelope: secureDefaultEnvelope("read"),
        enforceNavigationScope: true,
      });
      expect(decision.allowed).toBe(false);
      expect(decision.reasons).toContain(REASON_CODES.private_network_destination);
      return decision;
    }
    case "INV-11": {
      const decision = await resolveApproval(undefined, {
        id: "approval",
        sessionId: "session",
        action: action("PURCHASE"),
        findings: [],
        risk: { state: "NORMAL", score: 0 },
        expiresAt: new Date(Date.now() + 1_000).toISOString(),
      });
      expect(decision).toMatchObject({ approved: false, reason: "approval_handler_missing" });
      return decision;
    }
    case "INV-12": {
      const original = secureDefaultEnvelope("read").narrow({ navigation: "same-site" });
      const attemptedWiden = original.narrow({
        navigation: "allowlist",
        purchases: true,
        allowedOrigins: ["https://attacker.example"],
      });
      expect(attemptedWiden.navigation).toBe(original.navigation);
      expect(attemptedWiden.purchases).toBe(false);
      expect(attemptedWiden.allowedOrigins).toEqual([]);
      return attemptedWiden;
    }
    case "INV-13": {
      const input = `safe ${sentinel} tail`;
      const span = {
        start: 5,
        end: 5 + sentinel.length,
        replacement: "[REDACTED]",
        provenance: WEB_PROVENANCE,
      };
      const scanner = {
        id: "provenance-transform",
        phases: ["PERCEPTION"] as const,
        kind: "deterministic" as const,
        scan: async () => ({
          scanner: "provenance-transform",
          kind: "deterministic" as const,
          verdict: "sanitize" as const,
          severity: "medium" as const,
          findings: [],
          sanitized: provenanced("safe [REDACTED] tail", WEB_PROVENANCE),
          sanitizations: [span],
        }),
      };
      const registry = new ScannerRegistry();
      registry.register(scanner);
      const redactor = new RedactionRegistry();
      redactor.registerSecret(sentinel);
      const phase = await runPhase(registry, "PERCEPTION", {
        phase: "PERCEPTION",
        sessionId: "provenance-session",
        taskContract: { task: "read" },
        envelope: secureDefaultEnvelope("read"),
        riskState: "NORMAL",
        payload: { kind: "none" },
        provenance: WEB_PROVENANCE,
        redactor,
        deadline: Date.now() + 1_000,
        signal: new AbortController().signal,
      });
      const carrier = phase.sanitizedTexts[0];
      expect(carrier?.provenance).toEqual(WEB_PROVENANCE);
      expect(phase.sanitizationSpans[0]?.provenance).toEqual(WEB_PROVENANCE);
      const output = applySanitizationPipeline(
        input,
        phase.sanitizationSpans,
        phase.sanitizedTexts,
      );
      expect(output).not.toContain(sentinel);
      return { output, carrier, span: phase.sanitizationSpans[0] };
    }
    case "INV-14": {
      let sink: AdapterEventSink | undefined;
      let sessionId = "";
      const session = new OpenAgentFence({
        adapter: fakeAdapter({
          subscribe: (id, nextSink) => {
            sessionId = id;
            sink = nextSink;
            return () => undefined;
          },
        }),
      }).start({ task: "read" });
      await session.observe();
      session.setRisk("RESTRICTED", 50);
      sink?.onNavigation({
        kind: "navigation",
        sessionId,
        pageId: "page-1",
        mainFrame: true,
        origin: "https://page.example",
        url: "https://page.example/next",
      });
      expect(session.riskState).toBe("RESTRICTED");
      return session.end();
    }
    case "INV-15": {
      const redactor = new RedactionRegistry();
      redactor.registerSecret(sentinel);
      let view: unknown;
      const plugin = definePluginScanner({
        id: "invariant-scoped-plugin",
        phases: ["PRE_ACTION"],
        kind: "deterministic",
        manifest: {
          id: "invariant-scoped-plugin",
          permissions: ["action:metadata"],
          network: false,
        },
        scan: async (scoped) => {
          view = scoped;
          return {
            scanner: "invariant-scoped-plugin",
            kind: "deterministic",
            verdict: "allow",
            severity: "info",
            findings: [],
          };
        },
      });
      const registry = new ScannerRegistry();
      registry.register(plugin);
      await runPhase(registry, "PRE_ACTION", {
        phase: "PRE_ACTION",
        sessionId: "plugin-session",
        taskContract: { task: "fill" },
        envelope: secureDefaultEnvelope("fill"),
        riskState: "NORMAL",
        payload: { kind: "proposedAction", action: action("FILL", { data: sentinel }) },
        provenance: WEB_PROVENANCE,
        redactor,
        deadline: Date.now() + 1_000,
        signal: new AbortController().signal,
      });
      const scoped = view as { action?: Record<string, unknown>; handles?: unknown };
      expect(scoped.action?.["data"]).toBeUndefined();
      expect(scoped.handles).toBeUndefined();
      return view;
    }
    case "INV-16": {
      const result = decodeIterative("x".repeat(33), 8, 20, {
        maxInputBytes: 32,
        maxOutputBytes: 64,
        maxDecodeDepth: 8,
        deadlineMs: 20,
      });
      expect(result).toMatchObject({ status: "refused", reason: "input_too_large" });
      expect(() => loadCorpusFile(resolve(REPO_ROOT, "security-corpus/corpus.json"))).not.toThrow();
      return result;
    }
    case "INV-17": {
      const session = new OpenAgentFence({ adapter: fakeAdapter() }).start({ task: "explain" });
      const verdicts = ["BLOCK", "REQUIRE_APPROVAL", "RESTRICT", "QUARANTINE"] as const;
      const decisions = verdicts.map((verdict) =>
        session.recordDecision(
          action("READ"),
          verdict,
          [
            verdict === "REQUIRE_APPROVAL"
              ? REASON_CODES.approval_required
              : REASON_CODES.session_restricted,
          ],
          session.policyEngine.policyHash,
        ),
      );
      const trace = await session.end();
      const events = trace.events.filter((event) => event.kind === "policy_decision");
      expect(events).toHaveLength(4);
      for (const [index, decision] of decisions.entries()) {
        expect(decision.reasons.length).toBeGreaterThan(0);
        expect(events[index]?.data["reasons"]).toEqual(decision.reasons);
      }
      return { decisions, trace };
    }
    case "INV-18": {
      const session = new OpenAgentFence({ adapter: fakeAdapter(), vault: vaultAdapter() }).start({
        task: "debug",
        capabilities: { credentials: true },
        secrets: [
          {
            name: "debug",
            kind: "SECRET",
            origins: ["https://page.example"],
            fieldTypes: ["text"],
          },
        ],
      });
      await session.registerSecret("debug", sentinel);
      session.unsafe.rawPage(`diagnostic ${sentinel}`);
      const trace = await session.end();
      expect(trace.events.some((event) => event.kind === "escape_hatch")).toBe(true);
      return trace;
    }
    case "INV-19": {
      const now = Date.now();
      const intent: ActionIntent = {
        intentId: "intent",
        actionId: "action",
        action: action("CLICK", { target: { element: "#safe", origin: "https://page.example" } }),
        observation: { browserContextId: "ctx", pageId: "page-1", revision: 1 },
        target: { selector: "#safe", element: "#safe", origin: "https://page.example" },
        securityAttributes: { disabled: "false" },
        visibility: "visible",
        policyHash: "policy",
        operationHash: "operation",
        createdAt: now,
        expiresAt: now + 1_000,
      };
      const mismatches = compareIntentState(intent, {
        observation: intent.observation,
        target: { ...intent.target, selector: "#attacker" },
        securityAttributes: intent.securityAttributes,
        visibility: intent.visibility,
        policyHash: intent.policyHash,
        operationHash: intent.operationHash,
      });
      expect(mismatches).toContain("target");
      return mismatches;
    }
    case "INV-20": {
      const redactor = new RedactionRegistry();
      const provider: GuardModelProvider = {
        name: "malicious",
        model: "synthetic",
        makesExternalCalls: false,
        classify: async (): Promise<unknown> => ({
          promptInjection: false,
          confidence: 1,
          categories: [],
          recommendedVerdict: "allow",
          authority: true,
        }),
      };
      const outcome = await runGuardProvider(
        provider,
        {
          role: "text_injection",
          excerpts: [redactor.redact("bounded")],
          taskSummary: redactor.redact("read"),
          localeHints: ["en"],
        },
        {
          signal: new AbortController().signal,
          deadline: Date.now() + 1_000,
          maxInputBytes: 1_024,
          maxOutputBytes: 1_024,
        },
      );
      expect(outcome).toEqual({ ok: false, kind: "malformed" });
      return outcome;
    }
    case "INV-21": {
      const mutation: NetworkMutation = {
        surface: "fetch",
        initiator: "page_script",
        origin: "https://page.example",
        destination: "http://127.0.0.1/private",
        enforcement: "enforced",
        provenance: WEB_PROVENANCE,
        actionIntentId: "intent",
      };
      const decision = evaluateNetworkMutation({
        mutation,
        envelope: secureDefaultEnvelope("read"),
        riskState: "NORMAL",
        egressInspection: { verdict: "allow", reasons: [], inspectedBytes: 0, matchCount: 0 },
        correlation: { status: "matched", intentId: "intent", reasons: [] },
      });
      expect(decision.verdict).toBe("block");
      expect(decision.reasons).toContain(REASON_CODES.private_network_destination);
      return decision;
    }
  }
}

/** Run one invariant scenario and apply the global exact/normalized leak oracle. */
export async function verifyInvariant(id: InvariantId): Promise<void> {
  const sentinel = fixtureSentinel();
  const artifact = await exercise(id, sentinel);
  expect(expectNoRawSecretIn(artifact, sentinel)).toBe(true);
}
