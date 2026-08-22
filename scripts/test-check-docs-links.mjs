import { slugifyHeading } from "./check-docs-links.mjs";

function assertEqual(actual, expected, description) {
  if (actual !== expected) {
    throw new Error(
      `${description}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`,
    );
  }
}

const hostileHeading = "<script>alert(1)</script> **Release**";
const hostileAnchor = slugifyHeading(hostileHeading);
assertEqual(hostileAnchor, "alert1-release", "HTML must never reach an anchor");
if (/[<>]/u.test(hostileAnchor) || hostileAnchor.includes("script")) {
  throw new Error("hostile heading markup reached an anchor");
}
assertEqual(slugifyHeading("M0 — Repository"), "m0--repository", "normal heading anchor");
console.log("docs heading sanitization regression check passed");
