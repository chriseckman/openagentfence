export interface ResourceLimits {
  readonly maxNodes: number;
  readonly maxTextLength: number;
  readonly phaseDeadlineMs: number;
  readonly scannerConcurrency: number;
  readonly providerMaxInputBytes?: number;
  readonly providerMaxOutputBytes?: number;
  readonly providerMaxTokens?: number;
  readonly maxGuardCalls?: number;
  readonly maxGuardTokens?: number;
}

export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = {
  maxNodes: 2000,
  maxTextLength: 5000,
  phaseDeadlineMs: 1000,
  scannerConcurrency: 2,
  providerMaxInputBytes: 32_000,
  providerMaxOutputBytes: 16_000,
  providerMaxTokens: 4096,
  maxGuardCalls: 100,
  maxGuardTokens: 100_000,
};
