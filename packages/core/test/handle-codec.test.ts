import { describe, expect, it } from "vitest";
import { parseHandle, serializeHandle, mintHandle, detectHandles } from "../src/index.js";

describe("secret handle codec", () => {
  it("round-trips handles", () => {
    const h = mintHandle("SECRET", "api_key");
    expect(h.kind).toBe("SECRET");
    expect(h.name).toBe("api_key");
    expect(h.id).toMatch(/^[0-9a-f]{8}$/);
    expect(parseHandle(serializeHandle(h))).toEqual(h);
  });

  it("rejects malformed handles", () => {
    expect(parseHandle("not a handle")).toBeNull();
    expect(parseHandle("<SECRET:name>")).toBeNull();
    expect(parseHandle("<BOGUS:name:id>")).toBeNull();
  });

  it("finds handles inside URLs, form data, headers, paths, and nested objects", () => {
    const handle = "<SECRET:vendor_password:abcdef12>";
    const data = {
      url: `https://example.com/?token=${handle}`,
      headers: { authorization: `Bearer ${handle}` },
      nested: [{ file: `/tmp/${handle}` }],
    };
    const found = detectHandles(data);
    expect(found.length).toBeGreaterThanOrEqual(3);
    for (const h of found) {
      expect(h.name).toBe("vendor_password");
    }
  });

  it("does not match a plain string without a handle", () => {
    expect(detectHandles("hello world")).toEqual([]);
  });
});
