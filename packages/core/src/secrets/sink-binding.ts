/**
 * A sink binding ties a secret (by handle) to the origins and field types it
 * may ever be released to (ADR-0005). Resolution happens in `core`'s
 * `SecretResolver`; a vault implementation cannot weaken this.
 */
export interface SinkBinding {
  readonly origins: readonly string[];
  readonly fieldTypes: readonly string[];
  readonly selector?: string;
  readonly formAction?: string;
}

/** A request to resolve a handle against a concrete destination. */
export interface SinkTarget {
  readonly origin: string;
  readonly fieldType: string;
}
