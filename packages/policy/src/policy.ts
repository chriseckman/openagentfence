import type { PolicyEngine } from "@openagentfence/core";
import type { PolicyDocument } from "./document.js";
import { createPolicyEngine } from "./engine.js";
import { loadPolicyDocument } from "./load.js";

/** Load a policy document and construct its deterministic engine. @public */
export async function loadPolicy(input: string | PolicyDocument): Promise<PolicyEngine> {
  return createPolicyEngine(await loadPolicyDocument(input));
}
