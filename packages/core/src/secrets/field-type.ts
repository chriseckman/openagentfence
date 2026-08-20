const PASSWORD_HINT = /(?:^|[-_.])(pass(?:word|wd)?|pwd)(?:$|[-_.])/i;

const INPUT_FIELD_TYPES = new Set([
  "date",
  "datetime-local",
  "email",
  "month",
  "number",
  "password",
  "search",
  "tel",
  "text",
  "time",
  "url",
  "week",
]);

/**
 * Infer a secret sink field type from adapter-captured live element metadata.
 * Agent descriptions and proposed action text are deliberately not inputs.
 */
export function inferSecretFieldType(attributes: Readonly<Record<string, string>>): string | null {
  const tagName = attributes["tagName"]?.toLowerCase();
  const type = attributes["type"]?.toLowerCase();
  const autocomplete = attributes["autocomplete"]?.toLowerCase() ?? "";
  const identity = `${attributes["name"] ?? ""} ${attributes["id"] ?? ""}`;

  if (
    type === "password" ||
    autocomplete
      .split(/\s+/u)
      .some((token) => token === "current-password" || token === "new-password") ||
    PASSWORD_HINT.test(identity)
  ) {
    return "password";
  }
  if (tagName === "select") return "select";
  if (tagName === "textarea") return "text";
  if (tagName === "input" || type !== undefined) {
    if (type === "hidden" || type === "file") return null;
    return type !== undefined && INPUT_FIELD_TYPES.has(type) ? type : "text";
  }
  return attributes["role"]?.toLowerCase() === "textbox" ? "text" : null;
}
