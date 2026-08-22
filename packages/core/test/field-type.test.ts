import { describe, expect, it } from "vitest";
import { inferSecretFieldType } from "../src/index.js";

describe("live secret field-type inference", () => {
  it.each([
    [{ tagName: "input", type: "password" }, "password"],
    [{ tagName: "input", type: "text", autocomplete: "current-password" }, "password"],
    [{ tagName: "input", type: "text", id: "account-password" }, "password"],
    [{ tagName: "input", type: "email" }, "email"],
    [{ tagName: "textarea" }, "text"],
    [{ tagName: "select" }, "select"],
    [{ role: "textbox" }, "text"],
  ] as const)("infers bounded live metadata", (attributes, expected) => {
    expect(inferSecretFieldType(attributes)).toBe(expected);
  });

  it.each([
    { tagName: "input", type: "hidden" },
    { tagName: "input", type: "file" },
    { tagName: "button" },
    {},
  ])("rejects non-value or unknown sinks", (attributes) => {
    expect(inferSecretFieldType(attributes)).toBeNull();
  });
});
