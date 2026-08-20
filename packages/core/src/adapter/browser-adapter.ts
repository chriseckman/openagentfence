import type { PageObservation } from "./observation.js";
import type { BrowserAdapterCapabilities } from "./capabilities.js";
import type { Authorized } from "../action/authorized.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { NetworkMutation } from "../network/mutation.js";
import type { NetworkGuardDecision } from "../network/decision.js";
import type { EgressInspection } from "../egress/inspect.js";
import type { EgressPayload } from "../egress/payload.js";

export interface AdapterEventSink {
  onNavigation(event: AdapterEvent): void;
  /** Post-creation popup containment decision; `true` means close immediately. */
  onPopup(event: AdapterEvent): boolean;
  onDownload(event: AdapterEvent): void;
  onNetworkMutation?(mutation: NetworkMutation): void;
  /** Ephemeral pre-effect DLP check. Implementations must never retain `payload.value`. */
  onEgressPayload?(payload: EgressPayload, signal?: AbortSignal): EgressInspection;
  /** Synchronous firewall decision used only by adapters with an active request-abort hook. */
  onRouteRequest?(
    mutation: NetworkMutation,
    egressInspection?: EgressInspection,
  ): NetworkGuardDecision;
}

export interface AdapterEvent {
  readonly kind: "navigation" | "popup" | "download";
  readonly url?: string;
  readonly origin?: string;
  readonly sessionId: string;
  /** Adapter-stable opaque page identity; never derived from page content. */
  readonly pageId?: string;
  /** Adapter-stable opaque frame identity when the emitting frame is known. */
  readonly frameId?: string;
  /** Monotonic adapter-local page revision at the time the event was observed. */
  readonly revision?: number;
  /** True only when a navigation event came from the top-level page frame. */
  readonly mainFrame?: boolean;
}

/**
 * Framework-neutral browser contract (ADR-0002, ARCHITECTURE §3/§9). Adapters
 * implement this; `core` never imports Stagehand or Playwright. Only a branded
 * `AuthorizedAction` (state-bound, INV-19) reaches `executeAuthorized`; a raw
 * `CanonicalAction` is a compile-time error. The `SecretResolver` is scoped to
 * the action so values resolve only for bound sinks (TB5, TB7).
 */
export interface BrowserAdapter {
  readonly capabilities: BrowserAdapterCapabilities;

  observe(): Promise<PageObservation>;

  executeAuthorized(action: Authorized, resolver: SecretResolver): Promise<unknown>;

  /** Attach events to a firewall-owned session identity and return a disposer. */
  subscribe(sessionId: string, sink: AdapterEventSink): () => void;

  /** Raw framework handle, reachable only via the recorded escape hatch. */
  rawPage(reason: string): unknown;
}
