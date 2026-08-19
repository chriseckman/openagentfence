/**
 * The language-neutral, authorization-only policy document. Runtime provider
 * configuration, credentials, and executable callbacks are intentionally not
 * representable here (ADR-0008, ADR-0009).
 *
 * @public
 */
export interface PolicyDocument {
  readonly version: 1;
  readonly defaults?: {
    readonly unknown_action?: "block";
    readonly scanner_failure?: {
      readonly low_risk?: "warn" | "block";
      readonly high_risk?: "block";
    };
  };
  readonly navigation?: {
    readonly mode?: "same-site" | "same-origin" | "allowlist" | "none";
    readonly block_private_networks?: boolean;
    readonly max_redirect_hops?: number;
    /** Additional application-configured private/internal CIDR deny ranges. */
    readonly internal_network_ranges?: readonly string[];
  };
  readonly actions?: Partial<
    Readonly<
      Record<
        | "upload"
        | "delete"
        | "purchase"
        | "message"
        | "execute_script"
        | "download"
        | "authenticate"
        | "publish"
        | "change_setting",
        "deny" | "approval" | "allow"
      >
    >
  >;
  readonly secrets?: { readonly resolution?: "executor_only" };
  readonly injection?: {
    readonly high_confidence?: "restricted_mode" | "block";
    readonly critical?: "quarantine" | "block";
  };
  readonly budgets?: {
    readonly max_actions?: number;
    readonly max_duration_ms?: number;
    readonly max_navigations?: number;
    readonly on_exceeded?: "block" | "restricted_mode";
  };
  readonly scanners?: Readonly<
    Record<
      string,
      {
        readonly enabled?: boolean;
        readonly rules?: Readonly<
          Record<
            string,
            {
              readonly threshold?: number;
              readonly mode?: "warn" | "block";
              readonly origins?: Readonly<
                Record<string, { readonly threshold?: number; readonly mode?: "warn" | "block" }>
              >;
            }
          >
        >;
      }
    >
  >;
  readonly suppressions?: readonly {
    readonly rule: string;
    readonly scope: string;
    readonly justification: string;
    readonly expires?: string;
  }[];
  readonly risk?: {
    readonly restricted_at?: number;
    readonly quarantine_at?: number;
  };
}

const VALIDATED_POLICY_DOCUMENT: unique symbol = Symbol("openagentfence.policyDocument.validated");

/**
 * A deep-frozen document produced only by `loadPolicyDocument`. The brand
 * keeps arbitrary objects, including page-derived objects, out of PS-002's
 * deterministic engine construction path.
 *
 * @public
 */
export type ValidatedPolicyDocument = PolicyDocument & {
  readonly [VALIDATED_POLICY_DOCUMENT]: true;
};

/** Runtime guard for the immutable policy document trust boundary. @public */
export function isValidatedPolicyDocument(value: unknown): value is ValidatedPolicyDocument {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.isFrozen(value) &&
    Object.getOwnPropertySymbols(value).includes(VALIDATED_POLICY_DOCUMENT)
  );
}

export function brandPolicyDocument(document: PolicyDocument): ValidatedPolicyDocument {
  const branded = Object.defineProperty(document, VALIDATED_POLICY_DOCUMENT, {
    value: true as const,
    enumerable: false,
  }) as ValidatedPolicyDocument;
  return deepFreeze(branded);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const key of Object.getOwnPropertyNames(value)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}
