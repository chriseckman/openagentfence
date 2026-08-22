import type { CapabilityEnvelope } from "../envelope/envelope.js";
import { originOf } from "../action/url.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import { isPrivateNetworkDestination, isWithinInternalNetworkRanges } from "./private-network.js";

/** Immutable static constraints supplied by a policy engine, if any. */
export interface DestinationRules {
  /** Static policy may add a private-network block even when the contract requested it. */
  readonly blockPrivateNetworks: boolean;
  /** Additional application-configured CIDR ranges which are always blocked. */
  readonly internalNetworkRanges: readonly string[];
  /** Maximum redirect hops; a policy may only lower the secure default. */
  readonly maxRedirectHops: number;
}

/** Secure destination baseline. Policy and runtime layers may only narrow it. */
export const DEFAULT_DESTINATION_RULES: DestinationRules = Object.freeze({
  blockPrivateNetworks: false,
  internalNetworkRanges: Object.freeze([]),
  maxRedirectHops: 5,
});

export interface DestinationEvaluationInput {
  readonly destination: string;
  readonly sourceOrigin?: string;
  readonly enforceNavigationScope: boolean;
  readonly redirectHops?: number;
  readonly envelope: CapabilityEnvelope;
  readonly rules?: DestinationRules;
}

export interface DestinationEvaluation {
  readonly allowed: boolean;
  readonly reasons: readonly ReasonCode[];
}

export interface RedirectChainEvaluationInput {
  /** Origin of the request which began the chain. */
  readonly initialOrigin?: string;
  /** Each followed Location destination, in observed order. */
  readonly hops: readonly string[];
  readonly envelope: CapabilityEnvelope;
  readonly rules?: DestinationRules;
}

/**
 * Deterministically evaluate a browser destination before a request continues.
 * This operates only on trusted envelope/policy facts and bounded URL metadata;
 * page-provided navigation can therefore never expand the trusted scope.
 */
export function evaluateDestination(input: DestinationEvaluationInput): DestinationEvaluation {
  const rules = input.rules ?? DEFAULT_DESTINATION_RULES;
  const url = parseWebUrl(input.destination);
  if (url === null) return blocked(REASON_CODES.unsupported_url_scheme);
  if (
    ((rules.blockPrivateNetworks || !input.envelope.privateNetwork) &&
      isPrivateNetworkDestination(url.toString())) ||
    isWithinInternalNetworkRanges(url.toString(), rules.internalNetworkRanges)
  ) {
    return blocked(REASON_CODES.private_network_destination);
  }
  if (
    input.redirectHops !== undefined &&
    (!Number.isInteger(input.redirectHops) ||
      input.redirectHops < 0 ||
      input.redirectHops > rules.maxRedirectHops)
  ) {
    return blocked(REASON_CODES.redirect_hops_exceeded);
  }
  if (input.enforceNavigationScope) {
    const result = input.envelope.evaluate({
      type: "NAVIGATE",
      destination: url.toString(),
      ...(input.sourceOrigin !== undefined ? { target: { origin: input.sourceOrigin } } : {}),
    });
    if (!result.allowed) return { allowed: false, reasons: result.reasons };
  }
  return { allowed: true, reasons: [] };
}

/**
 * Evaluate every observed redirect hop in order. A later hop is never trusted
 * merely because an earlier hop was allowed; the first refusal terminates the
 * deterministic chain decision.
 */
export function evaluateRedirectChain(input: RedirectChainEvaluationInput): DestinationEvaluation {
  let sourceOrigin = input.initialOrigin;
  for (let index = 0; index < input.hops.length; index += 1) {
    const destination = input.hops[index];
    if (destination === undefined) return blocked(REASON_CODES.destination_not_allowed);
    const decision = evaluateDestination({
      destination,
      ...(sourceOrigin !== undefined ? { sourceOrigin } : {}),
      enforceNavigationScope: true,
      redirectHops: index + 1,
      envelope: input.envelope,
      ...(input.rules !== undefined ? { rules: input.rules } : {}),
    });
    if (!decision.allowed) return decision;
    sourceOrigin = destinationOrigin(destination) ?? undefined;
  }
  return { allowed: true, reasons: [] };
}

/** Only HTTP(S) destinations are allowed on guarded browser network surfaces. */
export function isSupportedNetworkScheme(href: string): boolean {
  return parseWebUrl(href) !== null;
}

function parseWebUrl(value: string): URL | null {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}

function blocked(reason: ReasonCode): DestinationEvaluation {
  return { allowed: false, reasons: [reason] };
}

/** A normalized HTTP(S) origin, or null for malformed/unsupported destinations. */
export function destinationOrigin(href: string): string | null {
  return originOf(href);
}
