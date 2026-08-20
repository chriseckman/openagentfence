import {
  defineScanner,
  destinationOrigin,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { makeFinding } from "../helpers.js";

/**
 * Advisory evidence for an attempted origin transition. Core destination
 * evaluation remains the final deterministic block (OAF-SEC-001).
 */
export function createCrossOriginNavigationScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "cross-origin-navigation",
    phases: ["PRE_ACTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      if (ctx.payload.kind !== "proposedAction" || ctx.payload.action.type !== "NAVIGATE") {
        return emptyResult();
      }
      const action = ctx.payload.action;
      const destination = action.destination;
      const sourceOrigin = action.target?.origin;
      if (destination === undefined || sourceOrigin === undefined) return emptyResult();
      const destinationOrigin = destinationOriginFor(destination);
      if (destinationOrigin === null || destinationOrigin === sourceOrigin) return emptyResult();
      const findings: Finding[] = [
        makeFinding(ctx, {
          id: "cross-origin-navigation:destination",
          category: "cross_origin_navigation",
          title: "Cross-origin navigation requested",
          description:
            "The requested navigation changes origin and requires deterministic scope evaluation.",
          sourceType: "url",
          origin: sourceOrigin,
          evidence: `${sourceOrigin} -> ${destinationOrigin}`,
          recommendedAction: "warn",
          severity: "medium",
        }),
      ];
      return {
        scanner: "cross-origin-navigation",
        kind: "deterministic",
        verdict: "warn",
        severity: "medium",
        findings,
      };
    },
  });
}

function emptyResult(): ScanResult {
  return {
    scanner: "cross-origin-navigation",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}

function destinationOriginFor(destination: string): string | null {
  return destinationOrigin(destination);
}
