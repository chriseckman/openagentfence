import type { ProvenancedDatum } from "../contracts/provenance.js";
import {
  createEgressInspector,
  type EgressInspection,
  type EgressInspector,
} from "../egress/inspect.js";
import type { EgressPayload } from "../egress/payload.js";
import {
  SourceValueRegistry,
  type SourceValueRegistration,
  type SourceValueRegistryLimits,
} from "./value-registry.js";

export interface SourceSinkCheck {
  register(datum: ProvenancedDatum<string>, signal?: AbortSignal): SourceValueRegistration;
  inspect(payload: EgressPayload, signal?: AbortSignal): EgressInspection;
  clear(): void;
  readonly size: number;
  readonly incomplete: boolean;
}

export interface SourceSinkCheckOptions {
  readonly isDestinationAllowed: (
    fingerprint: string,
    destinationOrigin: string,
    sink: EgressPayload["sink"],
    fieldType?: string,
  ) => boolean;
  readonly limits?: SourceValueRegistryLimits;
  readonly now?: () => number;
}

/** Compose the bounded provenance registry with the existing M4 DLP inspector. */
export function createSourceSinkCheck(options: SourceSinkCheckOptions): SourceSinkCheck {
  const registry = new SourceValueRegistry(options.limits, options.now);
  const inspector: EgressInspector = createEgressInspector({
    match: (value, signal) => registry.match(value, signal),
    isDestinationAllowed: options.isDestinationAllowed,
    ...(options.limits === undefined ? {} : { maxValueBytes: options.limits.maxValueBytes }),
  });
  return {
    register(datum, signal) {
      return registry.register(datum.value, datum.provenance, signal);
    },
    inspect(payload, signal) {
      return inspector.inspect(payload, signal);
    },
    clear() {
      registry.clear();
    },
    get size() {
      return registry.size;
    },
    get incomplete() {
      return registry.incomplete;
    },
  };
}
