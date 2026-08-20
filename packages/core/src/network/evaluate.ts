import type { CapabilityEnvelope } from "../envelope/envelope.js";
import type { EgressInspection } from "../egress/inspect.js";
import type { RiskState } from "../contracts/risk-state.js";
import { originOf, sameOrigin } from "../action/url.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import {
  DEFAULT_DESTINATION_RULES,
  evaluateDestination,
  type DestinationRules,
} from "./destination.js";
import type { NetworkGuardDecision } from "./decision.js";
import type { NetworkIntentCorrelation } from "./correlate.js";
import type { NetworkMutation } from "./mutation.js";

export interface NetworkMutationEvaluationInput {
  readonly mutation: NetworkMutation;
  readonly envelope: CapabilityEnvelope;
  readonly riskState: RiskState;
  readonly destinationRules?: DestinationRules;
  /** Required for an enforced surface; raw values remain outside this contract. */
  readonly egressInspection?: EgressInspection;
  /** Optional evidence only. It never removes an independently derived reason. */
  readonly correlation?: NetworkIntentCorrelation;
}

/**
 * Deterministic, adapter-neutral TB6 evaluation. Every enforced mutation is
 * decided from its current facts; observation-only/unavailable surfaces are
 * always returned as explicit gaps and never appear clean (INV-06/09/10/21).
 */
export function evaluateNetworkMutation(
  input: NetworkMutationEvaluationInput,
): NetworkGuardDecision {
  const { mutation, envelope } = input;
  const evidence = new Set<ReasonCode>(input.correlation?.reasons ?? []);
  const blocking = new Set<ReasonCode>();
  const destinationOrigin = originOf(mutation.destination);
  const sourceOrigin = mutation.origin === undefined ? null : originOf(mutation.origin);

  if (mutation.initiator === "unknown") evidence.add(REASON_CODES.unknown_network_initiator);
  if (mutation.provenance.trust !== "web" && mutation.provenance.trust !== "tool") {
    blocking.add(REASON_CODES.network_guard_failure);
  }
  if (sourceOrigin === null) blocking.add(REASON_CODES.network_origin_not_allowed);

  const navigationLike =
    mutation.surface === "navigation" ||
    mutation.surface === "redirect" ||
    mutation.surface === "form";
  const destination = evaluateDestination({
    destination: mutation.destination,
    ...(mutation.origin !== undefined ? { sourceOrigin: mutation.origin } : {}),
    enforceNavigationScope: navigationLike,
    ...(mutation.redirectHops !== undefined ? { redirectHops: mutation.redirectHops } : {}),
    envelope,
    rules: input.destinationRules ?? DEFAULT_DESTINATION_RULES,
  });
  if (!destination.allowed) for (const reason of destination.reasons) blocking.add(reason);

  if (
    destinationOrigin !== null &&
    sourceOrigin !== null &&
    !sameOrigin(destinationOrigin, sourceOrigin) &&
    !navigationLike
  ) {
    if (!envelope.externalCommunication) blocking.add(REASON_CODES.capability_denied);
    if (
      envelope.blockedOrigins.includes(destinationOrigin) ||
      !envelope.allowedOrigins.includes(destinationOrigin)
    ) {
      blocking.add(REASON_CODES.network_origin_not_allowed);
    }
    if (input.riskState !== "NORMAL") blocking.add(REASON_CODES.session_restricted);
  }
  if (input.riskState === "QUARANTINED") blocking.add(REASON_CODES.session_restricted);

  if (mutation.enforcement === "enforced") {
    if (input.egressInspection === undefined) {
      blocking.add(REASON_CODES.network_guard_failure);
    } else if (input.egressInspection.verdict === "block") {
      for (const reason of input.egressInspection.reasons) blocking.add(reason);
    }
    return {
      verdict: blocking.size === 0 ? "continue" : "block",
      reasons: [...blocking, ...evidence].filter(
        (reason, index, all) => all.indexOf(reason) === index,
      ),
      enforcement: mutation.enforcement,
    };
  }

  evidence.add(REASON_CODES.network_enforcement_unavailable);
  return {
    verdict: "observe_only_gap",
    reasons: [...blocking, ...evidence].filter(
      (reason, index, all) => all.indexOf(reason) === index,
    ),
    enforcement: mutation.enforcement,
  };
}
