import {
  actionEgressPayloads,
  defineScanner,
  detectHandles,
  hash,
  originOf,
  sameOrigin,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { makeFinding } from "../helpers.js";

const EXFIL_ACTIONS = new Set(["NAVIGATE", "SUBMIT", "UPLOAD", "MESSAGE", "PASTE"]);

/** Supporting evidence only; the fixed core layer-3 rule owns authorization. */
export function createSecretExfiltrationScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "secret-exfiltration",
    phases: ["MODEL_OUTPUT", "PRE_ACTION"],
    kind: "deterministic",
    timeoutMs: 50,
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      if (ctx.signal.aborted || Date.now() >= ctx.deadline) return incomplete(ctx);
      if (ctx.payload.kind === "modelOutput") {
        const handles = detectHandles(ctx.payload.output.content);
        return handles.length === 0
          ? clean()
          : evidence(ctx, "MODEL_OUTPUT", handles.length, 0, undefined);
      }
      if (ctx.payload.kind !== "proposedAction") return clean();
      const action = ctx.payload.action;
      if (!EXFIL_ACTIONS.has(action.type)) return clean();
      const handles = detectHandles(action);
      let registeredMatches = 0;
      for (const payload of actionEgressPayloads(action)) {
        const matched = ctx.redactor.matchEgress(payload.value, ctx.signal);
        if (matched.incomplete) return incomplete(ctx);
        registeredMatches += matched.fingerprints.length;
      }
      const sourceTrust = action.data?.provenance.trust ?? action.instructionProvenance.trust;
      const sourceTainted =
        sourceTrust === "web" || sourceTrust === "tool" || sourceTrust === "memory";
      if (handles.length === 0 && registeredMatches === 0 && !sourceTainted) return clean();

      const destination = action.destination ?? action.target?.origin;
      const destinationOrigin = destination === undefined ? null : originOf(destination);
      const sourceOrigin =
        action.target?.origin ??
        action.data?.provenance.origin ??
        action.instructionProvenance.origin;
      if (
        destinationOrigin !== null &&
        sourceOrigin !== undefined &&
        sameOrigin(destinationOrigin, sourceOrigin)
      ) {
        return clean();
      }
      return evidence(ctx, action.type, handles.length, registeredMatches, destination);
    },
  });
}

function evidence(
  ctx: SecurityContext,
  actionType: string,
  handleCount: number,
  registeredMatches: number,
  destination: string | undefined,
): ScanResult {
  const findings: Finding[] = [
    makeFinding(ctx, {
      id: "secret-exfiltration:cross-origin",
      category: "sensitive_egress_evidence",
      title: "Sensitive cross-origin egress evidence",
      description:
        "A tainted or sensitive value is associated with a cross-origin sink; the core rule decides authorization.",
      sourceType: "tool",
      provenance: ctx.provenance,
      evidence: `action=${actionType}; handles=${handleCount}; matches=${registeredMatches}; destinationHash=${
        destination === undefined ? "missing" : hash(destination).slice(0, 12)
      }`,
      recommendedAction: "warn",
      severity: "high",
      confidence: 1,
    }),
  ];
  return {
    scanner: "secret-exfiltration",
    kind: "deterministic",
    verdict: "warn",
    severity: "high",
    confidence: 1,
    findings,
  };
}

function clean(): ScanResult {
  return {
    scanner: "secret-exfiltration",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}

function incomplete(ctx: SecurityContext): ScanResult {
  return {
    scanner: "secret-exfiltration",
    kind: "deterministic",
    verdict: "block",
    severity: "critical",
    findings: [
      makeFinding(ctx, {
        id: "secret-exfiltration:incomplete",
        category: "scanner_unavailable",
        title: "Secret exfiltration evidence unavailable",
        description: "The bounded evidence scan could not complete.",
        sourceType: "tool",
        evidence: "secret exfiltration evidence scan incomplete",
        recommendedAction: "block",
        severity: "critical",
      }),
    ],
  };
}
