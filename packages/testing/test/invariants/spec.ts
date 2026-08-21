import { describe, it } from "vitest";
import { INVARIANT_COVERAGE, type InvariantId } from "./coverage-registry.js";
import { verifyInvariant } from "./scenario.js";

/** Define one stable, self-describing OAF-TEST-014 invariant group. */
export function invariantTest(id: InvariantId): void {
  const entry = INVARIANT_COVERAGE.find((candidate) => candidate.id === id);
  if (entry === undefined) throw new Error(`missing invariant registry entry: ${id}`);
  describe(`${entry.id}: ${entry.text}`, () => {
    it(`enforces ${entry.boundaries.join("/")} using ${entry.corpusCaseIds.join(",")}`, async () => {
      await verifyInvariant(id);
    });
  });
}
