/**
 * The package name of this library.
 * @public
 */
export const PACKAGE_NAME = "@openagentfence/policy";

export {
  isValidatedPolicyDocument,
  type PolicyDocument,
  type ValidatedPolicyDocument,
} from "./document.js";
export { loadPolicyDocument, parsePolicyDocumentSource, PolicyDocumentError } from "./load.js";
export { createPolicyEngine, hashPolicyDocument } from "./engine.js";
export { loadPolicy } from "./policy.js";
export {
  resolveScannerSuppression,
  resolveScannerThreshold,
  validatePolicy,
  type AppliedPolicySuppression,
  type PolicyValidationReport,
  type ScannerPolicyLookup,
  type ScannerThreshold,
} from "./validation.js";
