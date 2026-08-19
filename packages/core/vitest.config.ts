import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/**/*.ts"],
      // Count only files loaded during tests. Type-only modules (interfaces,
      // `export type`) compile to no runtime code and would otherwise report 0%.
      all: false,
      thresholds: { lines: 85, branches: 85, functions: 85, statements: 85 },
    },
  },
});
