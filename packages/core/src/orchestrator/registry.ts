import type { SecurityScanner } from "../scanner/scanner.js";
import type { SecurityPhase } from "../contracts/phase.js";

/**
 * Scanner registry (ARCHITECTURE §6). Registration is explicit (`defineScanner`
 * + import); there is no name-based loading. Duplicate ids are rejected.
 */
export class ScannerRegistry {
  private readonly scanners = new Map<string, SecurityScanner>();

  register(scanner: SecurityScanner): void {
    if (this.scanners.has(scanner.id)) {
      throw new Error(`scanner already registered: ${scanner.id}`);
    }
    this.scanners.set(scanner.id, scanner);
  }

  get(id: string): SecurityScanner | undefined {
    return this.scanners.get(id);
  }

  /** Scanners for a phase, deterministic first, then by ascending priority. */
  list(phase: SecurityPhase): SecurityScanner[] {
    const inPhase = [...this.scanners.values()].filter((s) => s.phases.includes(phase));
    return inPhase.sort(compareScanners);
  }

  all(): SecurityScanner[] {
    return [...this.scanners.values()].sort(compareScanners);
  }

  clear(): void {
    this.scanners.clear();
  }
}

function compareScanners(a: SecurityScanner, b: SecurityScanner): number {
  const kindA = a.kind === "deterministic" ? 0 : 1;
  const kindB = b.kind === "deterministic" ? 0 : 1;
  if (kindA !== kindB) {
    return kindA - kindB;
  }
  const priorityA = a.priority ?? Number.POSITIVE_INFINITY;
  const priorityB = b.priority ?? Number.POSITIVE_INFINITY;
  if (priorityA !== priorityB) {
    return priorityA - priorityB;
  }
  return a.id.localeCompare(b.id);
}
