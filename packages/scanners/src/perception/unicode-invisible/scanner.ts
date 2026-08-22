import {
  defineScanner,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { ZERO_WIDTH_CHARS } from "../../normalize/fold.js";
import { getProbe, makeFinding, observationOrigin } from "../../helpers.js";

/** Unicode-invisible / zero-width / bidi abuse scanner (OAF-BROWSER-009). */
export function createUnicodeInvisibleScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "unicode-invisible",
    phases: ["PERCEPTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      const probe = getProbe(ctx);
      if (probe === null) {
        return {
          scanner: "unicode-invisible",
          kind: "deterministic",
          verdict: "allow",
          severity: "info",
          findings: [],
        };
      }
      const origin = observationOrigin(ctx);
      const findings: Finding[] = [];

      const check = (label: string, text: string, selector?: string): void => {
        if (text.length === 0 || !ZERO_WIDTH_CHARS.test(text)) {
          return;
        }
        const count = (text.match(ZERO_WIDTH_CHARS) ?? []).length;
        findings.push(
          makeFinding(ctx, {
            id: `unicode:${label}`,
            category: "unicode_invisible",
            title: "Zero-width / invisible Unicode characters",
            description: `Text contains ${count} invisible or bidirectional control characters, which can hide or reorder content.`,
            sourceType: "dom",
            ...(selector !== undefined ? { selector } : {}),
            origin,
            evidence: text.slice(0, 200),
            recommendedAction: "warn",
            severity: "medium",
          }),
        );
      };

      for (const node of probe.nodes) {
        check(node.selector, node.text, node.selector);
        for (const [attr, value] of Object.entries(node.attributes)) {
          check(`${node.selector}:${attr}`, value, node.selector);
        }
      }
      probe.comments.forEach((comment, index) => check(`comment:${index}`, comment));

      return {
        scanner: "unicode-invisible",
        kind: "deterministic",
        verdict: findings.length > 0 ? "warn" : "allow",
        severity: findings.length > 0 ? "medium" : "info",
        findings,
      };
    },
  });
}
