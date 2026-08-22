import { describe, expect, it } from "vitest";
import { playwrightAdapter, wrapPage } from "../src/index.js";

describe("@openagentfence/playwright", () => {
  it("exports the adapter and wrapper factories", () => {
    expect(typeof playwrightAdapter).toBe("function");
    expect(typeof wrapPage).toBe("function");
  });
});
