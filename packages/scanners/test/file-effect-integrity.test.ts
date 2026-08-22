import { describe, expect, it } from "vitest";
import { provenanced, type CanonicalAction } from "@openagentfence/core";
import { createFileEffectIntegrityScanner } from "../src/index.js";
import { probe, scannerContext } from "./helpers.js";

function proposed(action: CanonicalAction) {
  const base = scannerContext(probe([]));
  return {
    ...base,
    phase: "PRE_ACTION" as const,
    payload: { kind: "proposedAction" as const, action },
  };
}

describe("file-effect integrity scanner (OAF-SEC-004)", () => {
  it("blocks a form without a bound action, a path-like upload, and a download without a source", async () => {
    const scanner = createFileEffectIntegrityScanner();
    const malformed: readonly CanonicalAction[] = [
      {
        type: "SUBMIT",
        data: provenanced({ method: "post" }, { trust: "application" }),
        instructionProvenance: { trust: "application" },
      },
      {
        type: "UPLOAD",
        destination: "https://upload.example/receive",
        data: provenanced(
          { files: [{ name: "C:\\private.txt", bytes: 1 }], taskNecessary: true },
          { trust: "application" },
        ),
        instructionProvenance: { trust: "application" },
      },
      { type: "DOWNLOAD", instructionProvenance: { trust: "application" } },
    ];
    for (const action of malformed) {
      const result = await scanner.scan(proposed(action));
      expect(result.verdict).toBe("block");
      expect(result.findings[0]?.category).toBe("malformed_file_effect");
    }
  });

  it("allows fully bound application-provided upload metadata", async () => {
    const result = await createFileEffectIntegrityScanner().scan(
      proposed({
        type: "UPLOAD",
        destination: "https://upload.example/receive",
        data: provenanced(
          {
            files: [{ name: "note.txt", bytes: 12, mimeType: "text/plain" }],
            provenance: { trust: "application" },
            sensitivity: "public",
            taskNecessary: true,
          },
          { trust: "application" },
        ),
        instructionProvenance: { trust: "application" },
      }),
    );
    expect(result.verdict).toBe("allow");
  });
});
