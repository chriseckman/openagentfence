/** Maximum raw text inspected per egress datum. Oversize required checks fail closed. */
export const MAX_EGRESS_VALUE_BYTES = 64 * 1024;

/**
 * Complete v0.1 D-11 representation set: exact, trim/case variants, one URL
 * encoding, and standard Base64. No recursive decoding or Unicode folding.
 */
export function egressMatchForms(value: string): readonly string[] {
  const trimmed = value.trim();
  const caseInputs = unique([
    value,
    ...(trimmed.length > 0 ? [trimmed] : []),
    value.toLowerCase(),
    value.toUpperCase(),
    ...(trimmed.length > 0 ? [trimmed.toLowerCase(), trimmed.toUpperCase()] : []),
  ]).filter((form) => form.length > 0);
  return unique([
    ...caseInputs,
    ...caseInputs.map((form) => encodeURIComponent(form)),
    ...caseInputs.map((form) => Buffer.from(form, "utf8").toString("base64")),
  ]);
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}
