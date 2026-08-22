# Persistent memory guard

OpenAgentFence never owns or implicitly writes an application's memory store.
The P0 API makes both trust-boundary transitions explicit:

```ts
import { OpenAgentFence, MemoryGuardError } from "@openagentfence/core";
import { defaultScanners } from "@openagentfence/scanners";

const session = new OpenAgentFence({ adapter, scanners: defaultScanners() }).start(contract);
const store = new Map<string, unknown>();

const write = await session.memory.guardWrite({
  content: pageDerivedFact,
  provenance: pageObservation.provenance,
});
if (write.allowed && write.item !== undefined) {
  store.set("fact", write.item); // application-owned storage
}

try {
  const data = session.memory.guardRead(store.get("fact"));
  // data.instructionEligible is always false; a valid read activates taint.
  provideDataToAgent(data);
} catch (error) {
  if (!(error instanceof MemoryGuardError)) throw error;
  // Invalid, tampered, cancelled, or post-session reads remain unavailable.
}
```

## Stored contract and integrity

A successful write returns schema version `1.0.0` with exactly
`schemaVersion`, `kind: "data"`, sanitized `content`, original `provenance`,
`contentHash`, `sensitivity`, and bounded controlled `markers`. The hash is
SHA-256 over a deterministic serialization of every field except the hash
itself. Reordering JSON properties is harmless; changing content, provenance,
sensitivity, markers, version, or kind invalidates the item. Unknown fields,
accessors, custom prototypes, duplicate/unknown markers, inputs above 100 KiB,
and malformed provenance are rejected.

`guardWrite()` requires the deterministic `memory-write` and
`secret-sensitive` scanners supplied by `defaultScanners()`. It removes or
marks instruction-like content, replaces detected secrets with an opaque
handle when a session vault is available (otherwise a redaction marker), and
returns no item when a required scan is missing, cancelled, late, malformed,
or exhausted. Findings and traces contain rule IDs, fingerprints, hashes, and
provenance only.

`guardRead()` never treats storage as authority. It validates and hashes before
release, wraps content as `UntrustedContent` with `trust: "memory"` while
retaining the original origin/frame/page/element/time metadata, forces
`instructionEligible: false`, and activates the session's web taint floor.
Enhanced read-time reinspection, schema migration, and cross-session policy
remain P1 under OAF-PROV-006.

Applications must route every persistence write and read through these two
calls; the firewall does not intercept an application-owned database. The
generated OAF-TEST-007 corpus exercises real local-page observations through
`guardWrite()`, JSON serialization, and fresh-session `guardRead()`. It covers
instruction removal, poisoned facts, vault-backed secret replacement, benign
facts, malformed/relabelled items, content/provenance hash tampering, complete
provenance retention, data-only release, and immediate taint activation. If no
vault is configured, detected sensitive material is replaced with a redaction
marker rather than being persisted raw.
