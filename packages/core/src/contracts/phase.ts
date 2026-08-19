export const SECURITY_PHASES = [
  "PERCEPTION",
  "MODEL_OUTPUT",
  "PRE_ACTION",
  "POST_ACTION",
  "PERSISTENCE",
  "EGRESS",
] as const;

export type SecurityPhase = (typeof SECURITY_PHASES)[number];

export function isSecurityPhase(value: string): value is SecurityPhase {
  return (SECURITY_PHASES as readonly string[]).includes(value);
}
