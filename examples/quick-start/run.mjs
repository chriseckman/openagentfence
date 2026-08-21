import { fileURLToPath } from "node:url";
// This repository-only runner imports the just-built workspace artifacts.
// The TypeScript example above continues to demonstrate the public imports.
import { OpenAgentFence, DEFAULT_NETWORK_CAPABILITIES } from "../../packages/core/dist/index.js";
import { loadPolicy } from "../../packages/policy/dist/index.js";
import { defaultScanners } from "../../packages/scanners/dist/index.js";

const adapter = {
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
    url: "https://example.test",
    origin: "https://example.test",
    frames: [],
    provenance: { trust: "web" },
  }),
  executeAuthorized: async () => undefined,
  subscribe: () => () => {},
  rawPage: () => ({ unavailable: true }),
};

const policy = await loadPolicy(fileURLToPath(new URL("./openagentfence.yml", import.meta.url)));
const firewall = new OpenAgentFence({ adapter, policy, scanners: defaultScanners() });
const session = firewall.start({ task: "read a local fixture" });

if (!session.envelope.evaluate({ type: "READ" }).allowed) {
  throw new Error("quick start did not retain secure READ capability");
}
if (session.envelope.evaluate({ type: "UPLOAD" }).allowed) {
  throw new Error("quick start unexpectedly widened UPLOAD capability");
}
await session.end();
console.log("quick-start offline composition passed");
