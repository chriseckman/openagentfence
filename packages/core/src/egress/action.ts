import type { CanonicalAction } from "../action/canonical-action.js";
import type { ActionIntent } from "../action/intent.js";
import type { DataProvenance } from "../contracts/provenance.js";
import { inferSecretFieldType } from "../secrets/field-type.js";
import { MAX_EGRESS_VALUE_BYTES } from "./match.js";
import type { EgressPayload, EgressSink } from "./payload.js";

const MAX_ACTION_EGRESS_VALUES = 128;
const MAX_ACTION_EGRESS_DEPTH = 6;

/** Build bounded ephemeral egress data from a canonical authorized-action candidate. */
export function actionEgressPayloads(
  action: CanonicalAction,
  intent?: ActionIntent,
): readonly EgressPayload[] {
  const payloads: EgressPayload[] = [];
  if (action.destination !== undefined) {
    try {
      const url = new URL(action.destination);
      if (url.search.length > 1) {
        payloads.push(
          payload(
            action.destination,
            "url_query",
            url.search.slice(1),
            action.instructionProvenance,
          ),
        );
      }
      if (url.hash.length > 1) {
        payloads.push(
          payload(
            action.destination,
            "url_fragment",
            url.hash.slice(1),
            action.instructionProvenance,
          ),
        );
      }
    } catch {
      // Destination validation owns malformed URLs; never fabricate content.
    }
  }

  if (action.data === undefined || !isDataEgressAction(action.type)) return payloads;
  const destination = action.destination ?? action.target?.origin ?? "";
  const strings: Array<{ readonly key: string; readonly value: string }> = [];
  const complete = collectStrings(action.data.value, "", 0, strings);
  const defaultSink = sinkFor(action.type);
  for (const item of strings) {
    const sink =
      action.type === "UPLOAD"
        ? /(?:^|\.)(?:path|filePath)$/i.test(item.key)
          ? "upload_path"
          : /(?:^|\.)(?:name|fileName)$/i.test(item.key)
            ? "upload_name"
            : "text_body"
        : defaultSink;
    const fieldType =
      sink === "typed_value" && intent !== undefined
        ? (inferSecretFieldType(intent.securityAttributes) ?? undefined)
        : undefined;
    payloads.push(payload(destination, sink, item.value, action.data.provenance, fieldType));
  }
  if (!complete) {
    payloads.push({
      destination,
      sink: defaultSink,
      value: "",
      byteLength: 0,
      complete: false,
      provenance: action.data.provenance,
    });
  }
  return payloads;
}

function payload(
  destination: string,
  sink: EgressSink,
  value: string,
  provenance: DataProvenance,
  fieldType?: string,
): EgressPayload {
  const byteLength = Buffer.byteLength(value, "utf8");
  return {
    destination,
    sink,
    value: byteLength <= MAX_EGRESS_VALUE_BYTES ? value : "",
    byteLength,
    complete: byteLength <= MAX_EGRESS_VALUE_BYTES,
    provenance,
    ...(fieldType !== undefined ? { fieldType } : {}),
  };
}

function collectStrings(
  value: unknown,
  key: string,
  depth: number,
  output: Array<{ readonly key: string; readonly value: string }>,
): boolean {
  if (depth > MAX_ACTION_EGRESS_DEPTH || output.length >= MAX_ACTION_EGRESS_VALUES) return false;
  if (Buffer.isBuffer(value)) {
    if (value.length > MAX_EGRESS_VALUE_BYTES) return false;
    output.push({ key, value: value.toString("utf8") });
    return true;
  }
  if (typeof value === "string") {
    output.push({ key, value });
    return output.length <= MAX_ACTION_EGRESS_VALUES;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ACTION_EGRESS_VALUES) return false;
    return value.every((item, index) => collectStrings(item, `${key}.${index}`, depth + 1, output));
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value);
    if (entries.length > MAX_ACTION_EGRESS_VALUES) return false;
    return entries.every(([name, item]) =>
      collectStrings(item, key.length === 0 ? name : `${key}.${name}`, depth + 1, output),
    );
  }
  return true;
}

function isDataEgressAction(type: CanonicalAction["type"]): boolean {
  return (
    type === "FILL" ||
    type === "TYPE" ||
    type === "MESSAGE" ||
    type === "SUBMIT" ||
    type === "UPLOAD" ||
    type === "PASTE"
  );
}

function sinkFor(type: CanonicalAction["type"]): EgressSink {
  if (type === "SUBMIT") return "form_body";
  if (type === "MESSAGE") return "message";
  if (type === "UPLOAD") return "text_body";
  return "typed_value";
}
