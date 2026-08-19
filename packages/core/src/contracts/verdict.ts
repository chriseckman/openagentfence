export const SCANNER_VERDICTS = ["allow", "warn", "sanitize", "approve", "block"] as const;

export type ScannerVerdict = (typeof SCANNER_VERDICTS)[number];

export const AGGREGATE_VERDICTS = [
  "ALLOW",
  "ALLOW_SANITIZED",
  "WARN",
  "RESTRICT",
  "REQUIRE_APPROVAL",
  "BLOCK",
  "QUARANTINE",
] as const;

export type AggregateVerdict = (typeof AGGREGATE_VERDICTS)[number];

/**
 * Scanner verdicts are lowercase *recommendations*; aggregate verdicts are
 * uppercase *decisions* (PRD §15, ARCHITECTURE §4). `RESTRICT` and `QUARANTINE`
 * are session-level and have no scanner equivalent.
 */
export const SCANNER_TO_AGGREGATE: Record<ScannerVerdict, AggregateVerdict> = {
  allow: "ALLOW",
  warn: "WARN",
  sanitize: "ALLOW_SANITIZED",
  approve: "REQUIRE_APPROVAL",
  block: "BLOCK",
};
