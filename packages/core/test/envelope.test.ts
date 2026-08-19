import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  compileTaskContract,
  secureDefaultEnvelope,
  envelopeAllowsAtLeast,
  REASON_CODES,
  validateTaskContract,
} from "../src/index.js";

function contract(input: unknown) {
  const r = validateTaskContract(input);
  if (!r.ok) {
    throw new Error(`bad contract: ${r.errors.join("; ")}`);
  }
  return r.value;
}

describe("capability envelope", () => {
  it("denies upload, submit, purchase, execute-script, cross-origin navigate, and private-network by default", () => {
    const env = secureDefaultEnvelope("t");
    expect(env.evaluate({ type: "UPLOAD" }).allowed).toBe(false);
    expect(env.evaluate({ type: "SUBMIT", destination: "https://shop.example/form" }).allowed).toBe(
      false,
    );
    expect(env.evaluate({ type: "PURCHASE" }).allowed).toBe(false);
    expect(env.evaluate({ type: "EXECUTE_SCRIPT" }).allowed).toBe(false);
    expect(
      env.evaluate({
        type: "NAVIGATE",
        destination: "https://evil.example",
        target: { origin: "https://shop.example" },
      }).allowed,
    ).toBe(false);
    expect(
      env.evaluate({ type: "NAVIGATE", destination: "http://169.254.169.254/latest" }).allowed,
    ).toBe(false);
  });

  it("denies unknown actions and private-network destinations with the right reasons", () => {
    const env = secureDefaultEnvelope("t");
    const unknown = env.evaluate({ type: "UNKNOWN" });
    expect(unknown.allowed).toBe(false);
    expect(unknown.reasons).toContain(REASON_CODES.unknown_action);

    const priv = env.evaluate({ type: "READ", destination: "http://127.0.0.1/" });
    expect(priv.allowed).toBe(false);
    expect(priv.reasons).toContain(REASON_CODES.private_network_destination);
  });

  it("allows reads and same-page actions by default", () => {
    const env = secureDefaultEnvelope("t");
    expect(env.evaluate({ type: "READ" }).allowed).toBe(true);
    expect(env.evaluate({ type: "SCROLL" }).allowed).toBe(true);
    expect(env.evaluate({ type: "CLICK" }).allowed).toBe(true);
  });

  it("honours a granted capability from the contract", () => {
    const c = contract({ task: "t", capabilities: { uploads: true } });
    const env = compileTaskContract(c);
    expect(env.evaluate({ type: "UPLOAD" }).allowed).toBe(true);
    expect(env.evaluate({ type: "PURCHASE" }).allowed).toBe(false);
  });

  it("requires external communication and destination scope for form submission", () => {
    const env = compileTaskContract(
      contract({
        task: "t",
        capabilities: { externalCommunication: true, navigation: "same-origin" },
      }),
    );
    expect(
      env.evaluate({
        type: "SUBMIT",
        target: { origin: "https://shop.example" },
        destination: "https://shop.example/checkout",
      }).allowed,
    ).toBe(true);
    expect(
      env.evaluate({
        type: "SUBMIT",
        target: { origin: "https://shop.example" },
        destination: "https://evil.example/collect",
      }).allowed,
    ).toBe(false);
  });

  it("narrow never widens the envelope (property)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          "downloads",
          "uploads",
          "purchases",
          "messaging",
          "destructiveActions",
          "credentials",
          "executeScript",
          "privateNetwork",
          "externalCommunication",
        ),
        fc.boolean(),
        (key, value) => {
          const env = compileTaskContract(
            contract({
              task: "t",
              capabilities: {
                uploads: true,
                downloads: true,
                purchases: true,
                executeScript: true,
                privateNetwork: true,
              },
            }),
          );
          const narrowed = env.narrow({ [key]: value });
          expect(envelopeAllowsAtLeast(env, narrowed)).toBe(true);
        },
      ),
    );
  });

  it("navigation narrows to a more restrictive mode only", () => {
    const env = compileTaskContract(
      contract({ task: "t", capabilities: { navigation: "allowlist" } }),
    );
    const narrowed = env.narrow({ navigation: "same-origin" });
    expect(narrowed.navigation).toBe("same-origin");
  });
});
