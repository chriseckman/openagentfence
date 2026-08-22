import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import {
  scanPackedContent,
  validateCycloneDxBom,
  validatePackedFiles,
  validatePackedManifest,
} from "./release-artifacts.mjs";

const valid = {
  bomFormat: "CycloneDX",
  specVersion: "1.7",
  serialNumber: "urn:uuid:12345678-1234-4234-8234-123456789abc",
  version: 1,
  components: Array.from({ length: 9 }, (_, index) => ({
    type: "library",
    name: `@openagentfence/test-${index}`,
    version: "0.1.0",
    purl: `pkg:npm/%40openagentfence%2Ftest-${index}@0.1.0`,
  })),
  dependencies: [],
};
assert.equal(validateCycloneDxBom(valid), true);
assert.throws(() => validateCycloneDxBom({ ...valid, specVersion: "1.6" }), /CycloneDX/);
assert.throws(() => validateCycloneDxBom({ ...valid, components: [] }), /every published package/);
const packedManifest = {
  name: "@openagentfence/example",
  version: "0.1.0-rc.1",
  dependencies: { "@openagentfence/core": "0.1.0-rc.1" },
};
assert.deepEqual(
  validatePackedManifest(packedManifest, "@openagentfence/example", "0.1.0-rc.1").dependencies,
  packedManifest.dependencies,
);
assert.throws(
  () =>
    validatePackedManifest(
      { ...packedManifest, dependencies: { "@openagentfence/core": "workspace:*" } },
      "@openagentfence/example",
      "0.1.0-rc.1",
    ),
  /non-publishable/,
);
assert.throws(
  () =>
    validatePackedManifest(
      { ...packedManifest, dependencies: { "@openagentfence/core": "0.0.0" } },
      "@openagentfence/example",
      "0.1.0-rc.1",
    ),
  /internal dependency outside the exact release set/,
);
assert.throws(
  () =>
    validatePackedManifest(
      { ...packedManifest, optionalDependencies: { local: "file:../local" } },
      "@openagentfence/example",
      "0.1.0-rc.1",
    ),
  /non-publishable/,
);
const allowedManifest = {
  files: ["dist", "README.md", "src/schemas/corpus-case.schema.json", "LICENSE", "NOTICE"],
};
validatePackedFiles(
  [
    "dist/index.js",
    "README.md",
    "src/schemas/corpus-case.schema.json",
    "LICENSE",
    "NOTICE",
    "package.json",
  ],
  allowedManifest,
  "@openagentfence/example",
);
assert.throws(
  () =>
    validatePackedFiles(
      ["src/index.js", "LICENSE", "NOTICE"],
      allowedManifest,
      "@openagentfence/example",
    ),
  /allowlist/,
);
const temporaryDirectory = mkdtempSync(resolve(tmpdir(), "openagentfence-release-artifact-"));
try {
  const credentialArchive = resolve(temporaryDirectory, "credential.tgz");
  writeFileSync(credentialArchive, gzipSync("AKIA1234567890ABCDEF"));
  assert.throws(
    () => scanPackedContent(credentialArchive, "@openagentfence/test"),
    /aws-access-key/,
  );
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
process.stdout.write("release artifact validation tests passed\n");
