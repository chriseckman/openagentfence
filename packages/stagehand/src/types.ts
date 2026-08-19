/** Structured action returned by Stagehand v4 `observe()` and accepted by
 * `act()`. The adapter validates this untrusted framework result at runtime
 * before it can reach authorization or execution.
 */
export interface StagehandObserveResult {
  /** Framework selector identifying the proposed target. */
  readonly selector: string;
  /** Untrusted human-readable description returned by Stagehand. */
  readonly description: string;
  /** Structured method to execute; absent candidates are not executable. */
  readonly method?: string | undefined;
  /** Structured method arguments, preserved exactly through authorization. */
  readonly arguments?: string[] | undefined;
}

/** Minimal structural form of Stagehand v4's versioned observe response. */
export interface StagehandObserveResponse {
  /** Untrusted candidate values returned by Stagehand v4. */
  readonly data: readonly unknown[];
  /** Opaque response metadata; never used as authorization authority. */
  readonly metadata?: unknown;
}

/**
 * Minimal Stagehand v4 surface used by the adapter. The public peer range and
 * exact development/conformance version are declared in package.json.
 */
export interface StagehandLike {
  /** Discover candidate structured actions without executing them. */
  observe(instruction?: string, options?: unknown): Promise<StagehandObserveResponse>;
  /** Execute a previously observed structured action without fresh inference. */
  act(action: StagehandObserveResult, options?: unknown): Promise<unknown>;
  /** Optional v4 extraction hook; outputs remain untrusted and are scanned. */
  extract?(input: unknown, options?: unknown): Promise<unknown>;
}
