import { describe, expect, it } from "vitest";
import {
  DEFAULT_DESTINATION_RULES,
  REASON_CODES,
  compileTaskContract,
  evaluateDestination,
  evaluateRedirectChain,
  isPrivateNetworkDestination,
  isValidInternalNetworkRange,
  isWithinInternalNetworkRanges,
  validateTaskContract,
} from "../src/index.js";

function envelope(input: object) {
  const result = validateTaskContract(input);
  if (!result.ok) throw new Error(result.errors.join("; "));
  return compileTaskContract(result.value);
}

describe("private/local destination classification (OAF-SEC-002)", () => {
  it.each([
    "http://localhost:9200/",
    "http://localhost.:9200/",
    "http://127.0.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://10.0.0.5/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal./computeMetadata/v1/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[fe80::1]/",
    "http://[fd00:ec2::254]/",
  ])("blocks the local form %s", (destination) => {
    expect(isPrivateNetworkDestination(destination)).toBe(true);
    expect(
      evaluateDestination({
        destination,
        enforceNavigationScope: false,
        envelope: envelope({ task: "read" }),
      }),
    ).toEqual({ allowed: false, reasons: [REASON_CODES.private_network_destination] });
  });

  it("recognizes bounded configured CIDR deny ranges", () => {
    expect(isValidInternalNetworkRange("198.18.0.0/15")).toBe(true);
    expect(isValidInternalNetworkRange("fd12:3456::/48")).toBe(true);
    expect(isValidInternalNetworkRange("not-a-range")).toBe(false);
    expect(isWithinInternalNetworkRanges("https://198.19.5.1/", ["198.18.0.0/15"])).toBe(true);
    expect(isWithinInternalNetworkRanges("https://example.com/", ["198.18.0.0/15"])).toBe(false);
  });
});

describe("canonical destination evaluation (OAF-SEC-001/002)", () => {
  it("honors allowlist and explicit blocklist before navigation", () => {
    const scope = envelope({
      task: "browse",
      capabilities: { navigation: "allowlist" },
      origins: {
        allow: ["https://shop.example", "https://cdn.shop.example"],
        block: ["https://cdn.shop.example"],
      },
    });
    expect(
      evaluateDestination({
        destination: "https://shop.example/catalog",
        sourceOrigin: "https://shop.example",
        enforceNavigationScope: true,
        envelope: scope,
      }).allowed,
    ).toBe(true);
    expect(
      evaluateDestination({
        destination: "https://cdn.shop.example/a.js",
        sourceOrigin: "https://shop.example",
        enforceNavigationScope: true,
        envelope: scope,
      }).reasons,
    ).toEqual([REASON_CODES.destination_not_allowed]);
  });

  it("allows same-site navigation but blocks a third-party destination", () => {
    const scope = envelope({ task: "browse", capabilities: { navigation: "same-site" } });
    expect(
      evaluateDestination({
        destination: "https://cdn.shop.example/assets",
        sourceOrigin: "https://shop.example",
        enforceNavigationScope: true,
        envelope: scope,
      }).allowed,
    ).toBe(true);
    expect(
      evaluateDestination({
        destination: "https://evil.example/",
        sourceOrigin: "https://shop.example",
        enforceNavigationScope: true,
        envelope: scope,
      }).reasons,
    ).toEqual([REASON_CODES.destination_not_allowed]);
  });

  it("denies all non-HTTP(S) scheme classes and redirect overflow", () => {
    const scope = envelope({
      task: "browse",
      capabilities: { navigation: "allowlist" },
      origins: { allow: ["https://shop.example"] },
    });
    for (const destination of [
      "javascript:alert(1)",
      "data:text/plain,x",
      "blob:https://shop.example/x",
      "file:///tmp/a",
      "custom:thing",
    ]) {
      expect(
        evaluateDestination({ destination, enforceNavigationScope: false, envelope: scope })
          .reasons,
      ).toEqual([REASON_CODES.unsupported_url_scheme]);
    }
    expect(
      evaluateDestination({
        destination: "https://shop.example/redirect",
        sourceOrigin: "https://shop.example",
        enforceNavigationScope: true,
        redirectHops: DEFAULT_DESTINATION_RULES.maxRedirectHops + 1,
        envelope: scope,
      }).reasons,
    ).toEqual([REASON_CODES.redirect_hops_exceeded]);
  });

  it("evaluates every redirect hop and never derives trusted scope from a page hop", () => {
    const scope = envelope({
      task: "browse",
      capabilities: { navigation: "allowlist" },
      origins: { allow: ["https://shop.example"] },
    });
    expect(
      evaluateRedirectChain({
        initialOrigin: "https://shop.example",
        hops: ["https://shop.example/first", "https://evil.example/collect"],
        envelope: scope,
      }).reasons,
    ).toEqual([REASON_CODES.destination_not_allowed]);
    expect(
      evaluateRedirectChain({
        initialOrigin: "https://shop.example",
        hops: Array.from({ length: 6 }, (_, index) => `https://shop.example/r${index}`),
        envelope: scope,
      }).reasons,
    ).toEqual([REASON_CODES.redirect_hops_exceeded]);
  });
});
