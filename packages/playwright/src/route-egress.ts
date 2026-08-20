import {
  MAX_EGRESS_VALUE_BYTES,
  type DataProvenance,
  type EgressInspection,
  type EgressPayload,
} from "@openagentfence/core";
import type { Request } from "playwright";

const MAX_HEADERS = 50;
const MAX_HEADER_VALUE_BYTES = 2048;

export function inspectRoutedEgress(
  request: Request,
  provenance: DataProvenance,
  inspect: (payload: EgressPayload, signal?: AbortSignal) => EgressInspection,
  signal?: AbortSignal,
): EgressInspection {
  const payloads = routePayloads(request, provenance);
  let inspectedBytes = 0;
  let matchCount = 0;
  const reasons = new Set<EgressInspection["reasons"][number]>();
  for (const payload of payloads) {
    const result = inspect(payload, signal);
    inspectedBytes += result.inspectedBytes;
    matchCount += result.matchCount;
    if (result.verdict === "block") for (const reason of result.reasons) reasons.add(reason);
  }
  return {
    verdict: reasons.size > 0 ? "block" : "allow",
    reasons: [...reasons],
    inspectedBytes,
    matchCount,
  };
}

function routePayloads(request: Request, provenance: DataProvenance): EgressPayload[] {
  const destination = request.url();
  const payloads: EgressPayload[] = [];
  try {
    const url = new URL(destination);
    if (url.search.length > 1) {
      payloads.push(payload(destination, "url_query", url.search.slice(1), provenance));
    }
  } catch {
    payloads.push(incomplete(destination, "url_query", provenance));
  }

  const headers = Object.entries(request.headers());
  if (headers.length > MAX_HEADERS) payloads.push(incomplete(destination, "header", provenance));
  for (const [, value] of headers.slice(0, MAX_HEADERS)) {
    const bytes = Buffer.byteLength(value, "utf8");
    payloads.push({
      destination,
      sink: "header",
      value: bytes <= MAX_HEADER_VALUE_BYTES ? value : "",
      byteLength: bytes,
      complete: bytes <= MAX_HEADER_VALUE_BYTES,
      provenance,
    });
  }

  const body = request.postDataBuffer();
  if (body !== null && body.length > 0) {
    const contentType = request.headers()["content-type"]?.toLowerCase() ?? "";
    const textual =
      contentType.length === 0 ||
      /(?:^|\/)(?:json|text)|x-www-form-urlencoded|xml|javascript/.test(contentType);
    payloads.push({
      destination,
      sink: contentType.includes("x-www-form-urlencoded") ? "form_body" : "routed_request_body",
      value: textual && body.length <= MAX_EGRESS_VALUE_BYTES ? body.toString("utf8") : "",
      byteLength: body.length,
      complete: textual && body.length <= MAX_EGRESS_VALUE_BYTES,
      provenance,
    });
  }
  return payloads;
}

function payload(
  destination: string,
  sink: EgressPayload["sink"],
  value: string,
  provenance: DataProvenance,
): EgressPayload {
  const byteLength = Buffer.byteLength(value, "utf8");
  return {
    destination,
    sink,
    value: byteLength <= MAX_EGRESS_VALUE_BYTES ? value : "",
    byteLength,
    complete: byteLength <= MAX_EGRESS_VALUE_BYTES,
    provenance,
  };
}

function incomplete(
  destination: string,
  sink: EgressPayload["sink"],
  provenance: DataProvenance,
): EgressPayload {
  return { destination, sink, value: "", byteLength: 0, complete: false, provenance };
}
