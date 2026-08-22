/**
 * Minimal built-in private/local-network destination check (ARCHITECTURE §3
 * forbidden-list exception: the Action Guard must always have this). The full
 * policy-configurable version is OAF-SEC-002; this covers loopback, RFC1918,
 * link-local, and cloud-metadata destinations so the envelope denies them by
 * default.
 */
export function isPrivateNetworkDestination(href: string): boolean {
  let host: string;
  try {
    host = new URL(href).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return false;
  }
  if (host === "") {
    return false;
  }
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  if (host === "metadata.google.internal" || host === "metadata") {
    return true;
  }
  if (host.startsWith("[") || host.includes(":")) {
    return isIpv6Private(host.replace(/^\[|\]$/g, ""));
  }
  return isIpv4Private(host);
}

function isIpv4Private(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const n = Number(part);
    if (n > 255) {
      return false;
    }
    nums.push(n);
  }
  const [a, b] = nums;
  // Unspecified / loopback.
  if (a === 0 || a === 127) {
    return true;
  }
  // RFC1918
  if (a === 10) {
    return true;
  }
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  // link-local / cloud metadata
  if (a === 169 && b === 254) {
    return true;
  }
  // Carrier-grade NAT is non-public address space and must not become an SSRF pivot.
  if (a === 100 && b !== undefined && b >= 64 && b <= 127) {
    return true;
  }
  return false;
}

function isIpv6Private(host: string): boolean {
  const words = ipv6Words(host);
  if (words === null) return false;
  const first = words[0] ?? 0;
  const last = words[7] ?? 0;
  // :: and ::1 are non-routable local destinations.
  if (words.slice(0, 7).every((word) => word === 0) && (last === 0 || last === 1)) return true;
  // IPv4-mapped IPv6 addresses inherit the IPv4 classification.
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
    const ipv4 = `${(words[6] ?? 0) >> 8}.${(words[6] ?? 0) & 0xff}.${last >> 8}.${last & 0xff}`;
    return isIpv4Private(ipv4);
  }
  // fc00::/7 (ULA) and fe80::/10 (link-local).
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}

/** Whether a literal destination is in a configured CIDR range. Invalid ranges never allow. */
export function isWithinInternalNetworkRanges(href: string, ranges: readonly string[]): boolean {
  let host: string;
  try {
    host = new URL(href).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  return ranges.some((range) => isInCidr(host, range));
}

/** Strict syntax validation for application-configured CIDR deny ranges. */
export function isValidInternalNetworkRange(range: string): boolean {
  const [network, prefixText, extra] = range.split("/");
  if (
    network === undefined ||
    prefixText === undefined ||
    extra !== undefined ||
    !/^\d+$/.test(prefixText)
  ) {
    return false;
  }
  const prefix = Number(prefixText);
  if (ipv4Value(network) !== null) return prefix >= 0 && prefix <= 32;
  return ipv6Words(network) !== null && prefix >= 0 && prefix <= 128;
}

function isInCidr(host: string, range: string): boolean {
  const [network, prefixText, extra] = range.split("/");
  if (
    network === undefined ||
    prefixText === undefined ||
    extra !== undefined ||
    !/^\d+$/.test(prefixText)
  ) {
    return false;
  }
  const prefix = Number(prefixText);
  const hostV4 = ipv4Value(host);
  const networkV4 = ipv4Value(network);
  if (hostV4 !== null && networkV4 !== null) {
    if (prefix < 0 || prefix > 32) return false;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (hostV4 & mask) === (networkV4 & mask);
  }
  const hostV6 = ipv6Words(host);
  const networkV6 = ipv6Words(network);
  if (hostV6 === null || networkV6 === null || prefix < 0 || prefix > 128) return false;
  for (let index = 0; index < 8; index += 1) {
    const remaining = prefix - index * 16;
    if (remaining <= 0) return true;
    const mask = remaining >= 16 ? 0xffff : (0xffff << (16 - remaining)) & 0xffff;
    if (((hostV6[index] ?? 0) & mask) !== ((networkV6[index] ?? 0) & mask)) return false;
  }
  return true;
}

function ipv4Value(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some((part) => part > 255)) return null;
  return (
    (((octets[0] ?? 0) << 24) |
      ((octets[1] ?? 0) << 16) |
      ((octets[2] ?? 0) << 8) |
      (octets[3] ?? 0)) >>>
    0
  );
}

function ipv6Words(value: string): readonly number[] | null {
  const normalized = value.toLowerCase();
  if (normalized.includes(".")) return null;
  const parts = normalized.split("::");
  if (parts.length > 2) return null;
  const leftSegment = parts.at(0);
  if (leftSegment === undefined) return null;
  const left = leftSegment === "" ? [] : leftSegment.split(":");
  const rightSegment = parts.length === 2 ? parts.at(1) : undefined;
  const right = rightSegment === undefined || rightSegment === "" ? [] : rightSegment.split(":");
  if (left.length + right.length > 8 || (parts.length === 1 && left.length !== 8)) return null;
  const words = [
    ...left,
    ...Array.from({ length: 8 - left.length - right.length }, () => "0"),
    ...right,
  ];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.map((word) => Number.parseInt(word, 16));
}
