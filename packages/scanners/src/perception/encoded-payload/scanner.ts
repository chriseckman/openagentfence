import {
  defineScanner,
  provenanced,
  type Finding,
  type ProbeResult,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { decodeIterative } from "../../normalize/decoders.js";
import { fold } from "../../normalize/fold.js";
import { DEFAULT_DECODE_LIMITS } from "../../normalize/limits.js";
import { classifyObservation, isVisibleClass } from "../visibility/classify.js";
import { scanInjection } from "../injection-heuristics/rules.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

interface Candidate {
  readonly label: string;
  readonly text: string;
  readonly selector?: string;
  readonly frameOrigin?: string;
  readonly nodeIndex?: number;
}

const NON_CONTENT_TAGS = new Set(["script", "style", "template", "code", "pre"]);

/**
 * Encoded/folded payload scanner (OAF-BROWSER-009). It considers bounded DOM
 * text, accessibility fields, attributes, comments, and structured metadata.
 * Only transformed text is scanned here; raw-text injection remains owned by
 * its surface scanner.
 */
export function createEncodedPayloadScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "encoded-payload",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    priority: 200,
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) return emptyResult();

      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];
      const unsafeNodes = new Set<number>();

      for (const candidate of candidates(probe)) {
        const text = candidate.text.trim();
        if (text.length === 0) continue;
        const decoded = decodeIterative(
          text,
          DEFAULT_DECODE_LIMITS.maxDecodeDepth,
          DEFAULT_DECODE_LIMITS.deadlineMs,
        );
        if (decoded.status === "refused") {
          findings.push(
            makeFinding(ctx, {
              id: `encoded:${candidate.label}:limit:${decoded.reason ?? "unknown"}`,
              category: "encoded_payload_limit",
              title: "Encoded payload could not be safely normalized",
              description: `Encoded content exceeded the ${decoded.reason ?? "unknown"} bound and was not treated as clean.`,
              sourceType: "dom",
              ...(candidate.selector === undefined ? {} : { selector: candidate.selector }),
              ...(candidate.frameOrigin === undefined
                ? {}
                : { frameOrigin: candidate.frameOrigin }),
              origin,
              evidence: text.slice(0, 200),
              recommendedAction: "warn",
              severity: "medium",
            }),
          );
          if (candidate.nodeIndex !== undefined) unsafeNodes.add(candidate.nodeIndex);
          continue;
        }

        const normalized = fold(decoded.text);
        const folded = normalized !== decoded.text;
        if (decoded.status === "unchanged" && !folded) continue;
        const chain = [...decoded.chain, ...(folded ? ["unicode-fold"] : [])];
        for (const match of scanInjection(normalized)) {
          findings.push(
            makeFinding(ctx, {
              id: `encoded:${candidate.label}:${match.ruleId}`,
              category: "encoded_instruction",
              title: "Instruction-like content in encoded payload",
              description: `Normalized payload (${chain.join(" -> ")}) contains ${match.category}`,
              sourceType: "dom",
              ...(candidate.selector === undefined ? {} : { selector: candidate.selector }),
              ...(candidate.frameOrigin === undefined
                ? {}
                : { frameOrigin: candidate.frameOrigin }),
              origin,
              evidence: match.evidence,
              recommendedAction: "block",
              severity: "high",
            }),
          );
          if (candidate.nodeIndex !== undefined) unsafeNodes.add(candidate.nodeIndex);
        }
      }

      const sanitized =
        unsafeNodes.size === 0
          ? undefined
          : provenanced(safeVisibleText(probe, unsafeNodes), ctx.provenance);
      return {
        scanner: "encoded-payload",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.some((finding) => finding.severity === "high")
          ? "high"
          : findings.length > 0
            ? "medium"
            : "info",
        findings,
        ...(sanitized === undefined ? {} : { sanitized }),
      };
    },
  });
}

function emptyResult(): ScanResult {
  return {
    scanner: "encoded-payload",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}

function candidates(probe: ProbeResult): readonly Candidate[] {
  const values: Candidate[] = [];
  probe.nodes.forEach((node, nodeIndex) => {
    // Script/code source is not agent-facing content. Scanning it would turn
    // inert fixture/application implementation strings into false positives.
    if (NON_CONTENT_TAGS.has(node.tagName)) return;
    values.push({
      label: `${node.selector}:text`,
      text: node.text,
      selector: node.selector,
      frameOrigin: node.frameOrigin,
      nodeIndex,
    });
    if (node.ariaLabel !== null) {
      values.push({
        label: `${node.selector}:aria-label`,
        text: node.ariaLabel,
        selector: node.selector,
        frameOrigin: node.frameOrigin,
      });
    }
    if (node.ariaDescription !== null) {
      values.push({
        label: `${node.selector}:aria-description`,
        text: node.ariaDescription,
        selector: node.selector,
        frameOrigin: node.frameOrigin,
      });
    }
    for (const [attribute, text] of Object.entries(node.attributes)) {
      values.push({
        label: `${node.selector}:${attribute}`,
        text,
        selector: node.selector,
        frameOrigin: node.frameOrigin,
      });
    }
  });
  probe.comments.forEach((text, index) => values.push({ label: `comment:${index}`, text }));
  values.push({ label: "title", text: probe.metadata.title });
  for (const [name, text] of Object.entries(probe.metadata.meta)) {
    values.push({ label: `meta:${name}`, text });
  }
  probe.metadata.jsonLd.forEach((text, index) => values.push({ label: `json-ld:${index}`, text }));
  probe.metadata.noscript.forEach((text, index) =>
    values.push({ label: `noscript:${index}`, text }),
  );
  return values;
}

function safeVisibleText(probe: ProbeResult, unsafeNodes: ReadonlySet<number>): string {
  return classifyObservation(probe)
    .nodes.filter((node, index) => isVisibleClass(node.visibility) && !unsafeNodes.has(index))
    .map((node) => node.node.text.trim())
    .filter((text) => text.length > 0)
    .join("\n");
}
