import type { NetworkInitiator } from "./initiator.js";
import type { EnforcementLevel, NetworkSurface } from "./capabilities.js";

/**
 * Bounded, redacted request metadata (OAF-CORE-017, INV-05/16). Headers carry
 * redacted values only; a body is represented by a hash and size, never by its
 * raw value. No unbounded or raw secret may appear here.
 */
export interface NetworkRequestMetadata {
  readonly method?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyHash?: string;
  readonly bodySize?: number;
}

/**
 * A single observed network effect, normalized independently of agent actions
 * (OAF-CORE-017, INV-21). The recorded initiator is factual; correlation to an
 * `ActionIntent` is carried only in `actionIntentId` when proven, and is
 * evidence — never authority.
 */
export interface NetworkMutation {
  readonly surface: NetworkSurface;
  readonly initiator: NetworkInitiator;
  readonly origin?: string;
  readonly frameOrigin?: string;
  readonly destination: string;
  readonly enforcement: EnforcementLevel;
  readonly metadata?: NetworkRequestMetadata;
  readonly actionIntentId?: string;
  /** Number of preceding redirect hops in this request chain, when observable. */
  readonly redirectHops?: number;
}
