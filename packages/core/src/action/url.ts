/**
 * URL origin/site normalization utilities (PRD §13.8).
 *
 * Site computation is an algorithmic approximation (last-two-labels of the
 * hostname) rather than a full public-suffix list. Documented limitation:
 * multi-label public suffixes (e.g. `co.uk`) are treated as a single site
 * suffix, so `a.co.uk` and `b.co.uk` will compare as the *same site*. A
 * bundled public-suffix list can replace this later.
 */

export function originOf(href: string): string | null {
  try {
    const url = new URL(href);
    return url.protocol === "http:" || url.protocol === "https:" ? url.origin : null;
  } catch {
    return null;
  }
}

export function hostnameOf(href: string): string | null {
  try {
    const url = new URL(href);
    return url.protocol === "http:" || url.protocol === "https:" ? url.hostname : null;
  } catch {
    return null;
  }
}

export function sameOrigin(a: string, b: string): boolean {
  const oa = originOf(a);
  const ob = originOf(b);
  return oa !== null && oa === ob;
}

export function sameSite(a: string, b: string): boolean {
  const ha = hostnameOf(a);
  const hb = hostnameOf(b);
  if (ha === null || hb === null) {
    return false;
  }
  return siteOfHost(ha) === siteOfHost(hb);
}

function siteOfHost(host: string): string {
  const lower = host.toLowerCase();
  if (isIpAddress(lower)) {
    return lower;
  }
  const labels = lower.split(".");
  if (labels.length <= 2) {
    return lower;
  }
  return labels.slice(labels.length - 2).join(".");
}

function isIpAddress(host: string): boolean {
  // Rough detection: IPv4 dotted quad or bracketed/coloned IPv6.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return true;
  }
  return host.includes(":") || host.startsWith("[");
}
