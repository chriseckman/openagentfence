import {
  NETWORK_SURFACES,
  type BrowserAdapterCapabilities,
  type EnforcementLevel,
} from "@openagentfence/core";
import { describePlaywrightCapabilities } from "@openagentfence/playwright";
import { CLI_EXIT, type CliIo } from "./common.js";

const PLAYWRIGHT_TESTED_VERSION = "1.62.1";
const PLAYWRIGHT_PEER_RANGE = ">=1.40.0";
const STAGEHAND_STATUS = "not_inspected" as const;

export interface ProviderConnectivityChecker {
  readonly check: (endpoint: URL, signal: AbortSignal) => Promise<"reachable">;
}

export interface DoctorDependencies {
  readonly nodeVersion?: string;
  readonly platform?: string;
  readonly providerChecker?: ProviderConnectivityChecker;
}

interface DoctorReport {
  readonly schemaVersion: "1.0.0";
  readonly node: { readonly version: string; readonly supported: boolean };
  readonly platform: string;
  readonly playwright: {
    readonly testedVersion: string;
    readonly peerRange: string;
    readonly capabilities: BrowserAdapterCapabilities;
    readonly gaps: readonly string[];
  };
  readonly stagehand: {
    readonly status: typeof STAGEHAND_STATUS;
    readonly reason: string;
  };
  readonly providerConnectivity: { readonly status: "not_checked" | "reachable" | "unavailable" };
}

export async function runDoctorCommand(
  args: readonly string[],
  io: CliIo,
  dependencies: DoctorDependencies = {},
): Promise<number> {
  const parsed = parseDoctorArgs(args);
  if (parsed === null) {
    io.stderr(
      "usage: openagentfence doctor [--json] [--route-requests] [--check-provider <https-url>]\n",
    );
    return CLI_EXIT.usage;
  }
  const capabilities = describePlaywrightCapabilities({ routeRequests: parsed.routeRequests });
  let providerStatus: DoctorReport["providerConnectivity"]["status"] = "not_checked";
  if (parsed.providerEndpoint !== undefined) {
    const checker = dependencies.providerChecker ?? { check: fetchConnectivity };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2_000);
    try {
      await checker.check(parsed.providerEndpoint, controller.signal);
      providerStatus = "reachable";
    } catch {
      providerStatus = "unavailable";
    } finally {
      clearTimeout(timer);
    }
  }
  const version = dependencies.nodeVersion ?? process.version;
  const report: DoctorReport = Object.freeze({
    schemaVersion: "1.0.0",
    node: Object.freeze({ version, supported: /^v?(2\d|[3-9]\d)\./u.test(version) }),
    platform: dependencies.platform ?? process.platform,
    playwright: Object.freeze({
      testedVersion: PLAYWRIGHT_TESTED_VERSION,
      peerRange: PLAYWRIGHT_PEER_RANGE,
      capabilities,
      gaps: Object.freeze(gaps(capabilities)),
    }),
    stagehand: Object.freeze({
      status: STAGEHAND_STATUS,
      reason: "not a CLI diagnostic dependency; consult the Stagehand package capability ledger",
    }),
    providerConnectivity: Object.freeze({ status: providerStatus }),
  });
  io.stdout(parsed.json ? `${JSON.stringify(report)}\n` : renderDoctor(report));
  return providerStatus === "unavailable" || !report.node.supported
    ? CLI_EXIT.failure
    : CLI_EXIT.success;
}

function parseDoctorArgs(args: readonly string[]): {
  readonly json: boolean;
  readonly routeRequests: boolean;
  readonly providerEndpoint?: URL;
} | null {
  let json = false;
  let routeRequests = false;
  let providerEndpoint: URL | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--json" && !json) {
      json = true;
      continue;
    }
    if (argument === "--route-requests" && !routeRequests) {
      routeRequests = true;
      continue;
    }
    if (argument === "--check-provider") {
      const value = args[index + 1];
      if (value === undefined || providerEndpoint !== undefined || value.length > 2_048)
        return null;
      try {
        const endpoint = new URL(value);
        if (endpoint.protocol !== "https:" && endpoint.protocol !== "http:") return null;
        providerEndpoint = endpoint;
      } catch {
        return null;
      }
      index += 1;
      continue;
    }
    return null;
  }
  return Object.freeze({
    json,
    routeRequests,
    ...(providerEndpoint === undefined ? {} : { providerEndpoint }),
  });
}

function gaps(capabilities: BrowserAdapterCapabilities): readonly string[] {
  return Object.freeze(
    NETWORK_SURFACES.filter(
      (surface) => capabilities.network[surface] !== ("enforced" satisfies EnforcementLevel),
    ).map((surface) => `${surface}:${capabilities.network[surface]}`),
  );
}

function renderDoctor(report: DoctorReport): string {
  const lines = [
    `node: ${report.node.version} (${report.node.supported ? "supported" : "unsupported"})`,
    `playwright: tested ${report.playwright.testedVersion}; peer ${report.playwright.peerRange}`,
    ...NETWORK_SURFACES.map(
      (surface) => `network ${surface}: ${report.playwright.capabilities.network[surface]}`,
    ),
    `stagehand: ${report.stagehand.status}`,
    `provider connectivity: ${report.providerConnectivity.status}`,
  ];
  return `${lines.join("\n")}\n`;
}

async function fetchConnectivity(endpoint: URL, signal: AbortSignal): Promise<"reachable"> {
  await fetch(endpoint, { method: "HEAD", redirect: "manual", signal });
  return "reachable";
}
