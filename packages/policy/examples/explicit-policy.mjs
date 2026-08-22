import { fileURLToPath } from "node:url";
import { loadPolicyDocument } from "../dist/index.js";

const policyPath = fileURLToPath(new URL("./openagentfence.yml", import.meta.url));
const document = await loadPolicyDocument(policyPath);

console.log(`Loaded OpenAgentFence policy version ${document.version}.`);
