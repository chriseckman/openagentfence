/**
 * The recorded escape hatch (PRD §18.5-18.6, INV-18). Every use is traced. It
 * is the only route to the raw framework handle; the secure wrapper covers all
 * other paths.
 */
export interface UnsafeAccess {
  rawPage(reason: string): unknown;
}
