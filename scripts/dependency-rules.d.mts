// Type declarations for the plain-ESM dependency-rules module.
// Kept alongside dependency-rules.mjs so TypeScript can resolve the module's
// types from tests without pulling build tooling into the scripts directory.

export interface DependencyViolation {
  package: string;
  dependency: string;
  reason: string;
}

export declare const ALLOWED_DEPENDENCIES: Record<string, string[]>;

export declare function dependencyViolations(
  packages: Record<string, string[]>,
): DependencyViolation[];
