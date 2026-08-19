import type { SecretHandle } from "./handle-codec.js";
import type { SinkTarget } from "./sink-binding.js";
import type { RiskState } from "../contracts/risk-state.js";

/** The subset of session state a resolver may consult when authorizing a sink. */
export interface ResolverSessionState {
  readonly riskState: RiskState;
  readonly permitsCredentialUse: boolean;
}

/**
 * The only path from a handle to a raw value (ADR-0005). Authorization logic
 * lives here, in `core`; the full sink-bound implementation is OAF-DATA-003.
 * Until then the stub always denies.
 */
export interface SecretResolver {
  resolveForSink(
    handle: SecretHandle,
    target: SinkTarget,
    state: ResolverSessionState,
  ): Promise<string | null>;
}

/** OAF-CORE-013 stub: always denies and returns null (fail closed). */
export const denyAllResolver: SecretResolver = {
  async resolveForSink(): Promise<string | null> {
    return null;
  },
};
