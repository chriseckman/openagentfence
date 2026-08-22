import type { GuardClassificationRequest } from "./request.js";
import type { GuardExecutionConstraints } from "./execution.js";

/**
 * Interface-only provider boundary in `core` (ADR-0004, ADR-0009). `core`
 * bundles no model and no vendor SDK; implementations live in
 * `@openagentfence/providers`, and `OpenAgentFence` receives only an
 * instantiated provider. `classify` returns `unknown`: provider output is
 * untrusted and must cross `runGuardProvider` validation before use (TB3).
 */
export interface GuardModelProvider {
  readonly name: string;
  readonly model: string;
  readonly makesExternalCalls: boolean;
  classify(
    request: GuardClassificationRequest,
    constraints: GuardExecutionConstraints,
  ): Promise<unknown>;
}
