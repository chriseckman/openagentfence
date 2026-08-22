import type { GuardModelProvider } from "@openagentfence/core";
import type { GuardProviderOptions } from "./config.js";
import { GuardProviderConstructionError, validateProviderOptions } from "./config.js";

/**
 * Reserved optional OpenCode entry point.
 *
 * OpenCode 1.18.x documents an agent-session HTTP/SDK surface, but no verified
 * tool-free strict-JSON classification call. D-03 therefore requires a typed
 * construction failure instead of adapting the agentic message endpoint.
 */
export function openCodeGuardProvider(options: GuardProviderOptions): GuardModelProvider {
  validateProviderOptions(options);
  throw new GuardProviderConstructionError("provider_unavailable");
}
