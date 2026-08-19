export const SCANNER_PERMISSIONS = [
  "page:visible_text",
  "page:hidden_text",
  "page:redacted_text",
  "page:screenshot",
  "action:metadata",
  "action:data",
  "secrets:handles",
] as const;

export type ScannerPermission = (typeof SCANNER_PERMISSIONS)[number];

/**
 * Plugin manifest (PRD §22). `network` is a separate boolean (PRD also lists
 * `network:outbound`, normalised here to the boolean per ARCHITECTURE §15).
 */
export interface PluginManifest {
  readonly id: string;
  readonly version?: string;
  readonly permissions: readonly ScannerPermission[];
  readonly network: boolean;
}
