import {
  defineScanner,
  isPrivateNetworkDestination,
  isSupportedNetworkScheme,
  type Finding,
  type ScanResult,
  type SecurityContext,
} from "@openagentfence/core";
import { makeFinding } from "../helpers.js";

/** Advisory SSRF/scheme evidence; core and routed adapters remain final controls. */
export function createLocalNetworkSsrfScanner(): ReturnType<typeof defineScanner> {
  return defineScanner({
    id: "local-network-ssrf",
    phases: ["PRE_ACTION"],
    kind: "deterministic",
    async scan(ctx: SecurityContext): Promise<ScanResult> {
      if (ctx.payload.kind !== "proposedAction") return emptyResult();
      const destination = ctx.payload.action.destination;
      if (destination === undefined) return emptyResult();
      const origin = ctx.payload.action.target?.origin;
      const findings: Finding[] = [];
      if (!isSupportedNetworkScheme(destination)) {
        findings.push(
          makeFinding(ctx.redactor, {
            id: "local-network-ssrf:unsupported-scheme",
            category: "unsafe_destination_scheme",
            title: "Unsupported destination scheme",
            description: "A guarded navigation destination must use HTTP or HTTPS.",
            sourceType: "url",
            ...(origin !== undefined ? { origin } : {}),
            evidence: destination.slice(0, 200),
            recommendedAction: "warn",
            severity: "high",
          }),
        );
      } else if (isPrivateNetworkDestination(destination)) {
        findings.push(
          makeFinding(ctx.redactor, {
            id: "local-network-ssrf:private-destination",
            category: "private_network_destination",
            title: "Private/local destination requested",
            description:
              "The destination resolves to a local, private, link-local, or metadata address form.",
            sourceType: "url",
            ...(origin !== undefined ? { origin } : {}),
            evidence: destination.slice(0, 200),
            recommendedAction: "warn",
            severity: "high",
          }),
        );
      }
      return findings.length === 0
        ? emptyResult()
        : {
            scanner: "local-network-ssrf",
            kind: "deterministic",
            verdict: "warn",
            severity: "high",
            findings,
          };
    },
  });
}

function emptyResult(): ScanResult {
  return {
    scanner: "local-network-ssrf",
    kind: "deterministic",
    verdict: "allow",
    severity: "info",
    findings: [],
  };
}
