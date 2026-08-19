/**
 * Synthetic TaskContract fixtures (INV-05: synthetic values and secret handles
 * only; no real credentials).
 */

export const NESTED_CONTRACT: unknown = {
  task: "find a refundable hotel",
  capabilities: {
    navigation: "allowlist",
    downloads: true,
    uploads: false,
  },
  secrets: [
    {
      name: "vendor_password",
      kind: "SECRET",
      origins: ["https://auth.vendor.example"],
      fieldTypes: ["password"],
    },
    {
      name: "profile_email",
      kind: "PII",
      origins: ["https://shop.example"],
      fieldTypes: ["text"],
    },
  ],
  origins: {
    allow: ["https://shop.example", "https://auth.vendor.example"],
    block: ["https://evil.example"],
  },
  budgets: {
    maxActions: 20,
    maxDurationMs: 60000,
    maxNavigations: 5,
  },
  approval: {
    required: true,
    timeoutMs: 30000,
  },
};

export const INVALID_CONTRACTS: readonly unknown[] = [
  null,
  [],
  "not-an-object",
  { task: "x", bogus: 1 },
  { task: "x", capabilities: { hacker: true } },
  { task: "x", secrets: [{ name: "a", kind: "SECRET", origins: "nope", fieldTypes: [] }] },
];
