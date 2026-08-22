export interface DecodeLimits {
  readonly maxInputBytes: number;
  readonly maxDecodeDepth: number;
  readonly maxOutputBytes: number;
  readonly deadlineMs: number;
}

export const DEFAULT_DECODE_LIMITS: DecodeLimits = {
  maxInputBytes: 100_000,
  maxDecodeDepth: 8,
  maxOutputBytes: 50_000,
  deadlineMs: 20,
};

export class DecodeLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecodeLimitError";
  }
}
