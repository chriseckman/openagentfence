import { fileURLToPath } from "node:url";
import { OpenAgentFence, type BrowserAdapter } from "@openagentfence/core";
import { loadPolicy } from "@openagentfence/policy";
import { defaultScanners } from "@openagentfence/scanners";

/**
 * Builds a scanner-enabled firewall with an application-supplied adapter.
 * The example performs no browser navigation, provider call, or credential
 * lookup. Applications own adapter and optional provider construction.
 */
export async function createQuickStart(adapter: BrowserAdapter): Promise<OpenAgentFence> {
  const policy = await loadPolicy(fileURLToPath(new URL("./openagentfence.yml", import.meta.url)));
  return new OpenAgentFence({ adapter, policy, scanners: defaultScanners() });
}
