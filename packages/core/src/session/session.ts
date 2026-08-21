import { randomBytes } from "node:crypto";
import type { CapabilityEnvelope } from "../envelope/envelope.js";
import type { RiskState, SessionRisk } from "../contracts/risk-state.js";
import { maxRiskState } from "../contracts/risk-state.js";
import type { TaskContract } from "../contracts/task-contract.js";
import type { CanonicalAction } from "../action/canonical-action.js";
import type { ActionIntent } from "../action/intent.js";
import { isIntentExpired } from "../action/intent.js";
import {
  comparePostAction,
  POST_ACTION_MAX_EVENTS,
  POST_ACTION_SETTLE_MS,
  postActionCapabilitiesAvailable,
  type PostActionObservation,
  type PostActionStatus,
} from "../action/post-action.js";
import { mintAuthorizedAction, type Authorized } from "../action/authorized.js";
import { stableSerialize } from "../action/state-fingerprint.js";
import {
  createScopedSecretResolver,
  denyAllResolver,
  type ScopedSecretResolver,
} from "../secrets/resolver.js";
import { wrapUntrustedContent, type UntrustedContent } from "../contracts/untrusted-content.js";
import {
  leastTrust,
  provenanced,
  validateDataProvenance,
  type DataProvenance,
  type ProvenancedDatum,
} from "../contracts/provenance.js";
import type { Finding } from "../contracts/finding.js";
import type { AggregateVerdict } from "../contracts/verdict.js";
import type { BrowserAdapter } from "../adapter/browser-adapter.js";
import type { AdapterEvent, AdapterEventSink } from "../adapter/browser-adapter.js";
import type { NetworkMutation } from "../network/mutation.js";
import { DEFAULT_DESTINATION_RULES } from "../network/destination.js";
import { correlateNetworkMutation } from "../network/correlate.js";
import { evaluateNetworkMutation } from "../network/evaluate.js";
import type { SessionVault } from "../secrets/vault-adapter.js";
import { createVaultExecutorAccess, type VaultExecutorAccess } from "../secrets/vault-access.js";
import { createUnsafeAdapterAccess } from "../adapter/raw-access.js";
import { STAGEHAND_EXECUTION, type ExactActionExecutor } from "../internal.js";
import type { PolicyEngine } from "../policy/engine.js";
import {
  SessionBudgetLedger,
  systemSessionClock,
  type BudgetUse,
  type SessionClock,
} from "./budgets.js";
import type { GuardModelProvider } from "../guard/provider.js";
import type { GuardClassificationRequest } from "../guard/request.js";
import {
  DEFAULT_GUARD_EXECUTION_LIMITS,
  runGuardProvider,
  type GuardProviderOutcome,
} from "../guard/execution.js";
import type { TraceWriter } from "../trace/writer.js";
import { redactDeep } from "../trace/writer.js";
import type { TraceDocument, EvidenceReference } from "../trace/events.js";
import { hash, type RedactionRegistry } from "../trace/redact.js";
import type { PageObservation } from "../adapter/observation.js";
import type { SecurityPhase } from "../contracts/phase.js";
import type { SecurityContext, PhasePayload } from "../scanner/context.js";
import { ScannerRegistry } from "../orchestrator/registry.js";
import { runPhase, type PhaseTierMetric } from "../orchestrator/run-phase.js";
import { type ResourceLimits } from "../orchestrator/limits.js";
import { applySanitizationPipeline, type SanitizationSpan } from "../orchestrator/sanitize.js";
import { riskAggregator } from "../risk/aggregator.js";
import { applyRiskSignal, type RiskSignal } from "../risk/engine.js";
import type { RiskAssessment } from "../contracts/risk-assessment.js";
import { isCrossOrigin, isHighImpact } from "../action/classify.js";
import { originOf, sameOrigin, sameSite } from "../action/url.js";
import { detectHandles, serializeHandle, type SecretHandle } from "../secrets/handle-codec.js";
import { isReasonCode, REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import type { ApprovalDecision, ApprovalHandler, ApprovalRequest } from "./approval.js";
import { resolveApproval } from "./approval.js";
import type { SessionDecision, SessionEvents } from "./events.js";
import { actionEgressPayloads } from "../egress/action.js";
import type { EgressInspection } from "../egress/inspect.js";
import type { EgressPayload } from "../egress/payload.js";
import { EGRESS_SINKS } from "../egress/payload.js";
import { evaluateCrossOriginExfiltration } from "../egress/exfiltration.js";
import { createSourceSinkCheck, type SourceSinkCheck } from "../provenance/source-sink.js";
import { DEFAULT_SOURCE_VALUE_LIMITS } from "../provenance/value-registry.js";
import {
  MemoryGuardError,
  type MemoryGuardReason,
  type MemoryWriteResult,
  type SessionMemoryGuard,
} from "../memory/guard.js";
import {
  createStoredMemoryItem,
  memoryItemHash,
  memoryReadDatum,
  memoryWriteCandidateExceedsBounds,
  validateMemoryWriteCandidate,
  validateStoredMemoryItemShape,
  type MemoryWriteCandidate,
  type MemoryMarker,
} from "../memory/item.js";

const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;

interface ActivePostAction {
  readonly action: CanonicalAction;
  readonly intent: ActionIntent;
  readonly startedOrigin: string | undefined;
  readonly events: AdapterEvent[];
  status: PostActionStatus;
}

interface SensitiveEgressBinding {
  readonly origins: ReadonlySet<string>;
  readonly fieldTypes: ReadonlySet<string>;
}

interface ActionEgressEvaluation {
  readonly reasons: readonly ReasonCode[];
  readonly matchCount: number;
}

export interface SecuritySessionInit {
  readonly id: string;
  readonly adapter: BrowserAdapter;
  readonly contract: TaskContract;
  readonly envelope: CapabilityEnvelope;
  readonly policy: PolicyEngine;
  readonly registry: ScannerRegistry;
  readonly redactor: RedactionRegistry;
  readonly limits: ResourceLimits;
  readonly guardModel?: GuardModelProvider;
  readonly vault?: SessionVault;
  /** @internal Session-private capability supplied by `OpenAgentFence`. */
  readonly vaultAccess?: VaultExecutorAccess;
  readonly approvalHandler?: ApprovalHandler;
  readonly trace: TraceWriter;
  readonly clock?: SessionClock;
}

export interface PerceptionResult {
  readonly observation: PageObservation;
  /** Sanitized text is still untrusted and carries its original source. */
  readonly sanitizedText: ProvenancedDatum<string>;
  readonly findings: readonly Finding[];
  readonly assessment: RiskAssessment;
}

/** Result of binding a successful session decision to adapter-inspected state. */
export interface BoundAuthorizationResult {
  readonly decision: SessionDecision;
  readonly authorized?: Authorized;
}

/**
 * Trusted TB1 declaration for an action batch. It is deliberately available
 * only on the firewall-owned batch API; caller-supplied `trust: "user"` on a
 * raw action is rejected.
 */
export interface TrustedInstructionOptions {
  readonly instructedBy?: "user";
}

/** Session-owned limits for one bounded guard-provider dispatch. */
export interface SessionGuardExecution {
  readonly signal: AbortSignal;
  readonly deadline: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
  readonly maxTokens?: number;
}

/** Session-owned, budget-consuming semantic guard dispatch capability. */
export type SessionGuardClassifier = (
  request: GuardClassificationRequest,
  execution: SessionGuardExecution,
) => Promise<GuardProviderOutcome>;

/** Creates one guard-backed scanner per session without exposing the provider. */
export type SessionGuardScannerFactory = (
  classify: SessionGuardClassifier,
) => import("../scanner/scanner.js").SecurityScanner;

/**
 * One browser context = one session (ARCHITECTURE §5). Owns the envelope, risk
 * state, trace, event stream, approval plumbing, and the escape hatch, and
 * runs the minimal perceive/authorize pipeline used by the M2 vertical slice.
 */
export class SecuritySession {
  readonly id: string;
  readonly envelope: CapabilityEnvelope;
  readonly memory: SessionMemoryGuard;

  private readonly adapter: BrowserAdapter;
  private readonly contract: TaskContract;
  private readonly policy: PolicyEngine;
  private readonly registry: ScannerRegistry;
  private requiredGuardUnavailable = false;
  private readonly redactor: RedactionRegistry;
  private readonly limits: ResourceLimits;
  private readonly guardModel: GuardModelProvider | undefined;
  private readonly vault: SessionVault | undefined;
  private readonly vaultAccess: VaultExecutorAccess | undefined;
  private readonly rawAdapterAccess = createUnsafeAdapterAccess();
  private readonly approvalHandler: ApprovalHandler | undefined;
  private readonly trace: TraceWriter;
  private readonly budgets: SessionBudgetLedger;
  private readonly clock: SessionClock;

  private risk: RiskState = "NORMAL";
  private score = 0;
  private currentOrigin: string | undefined;
  /** Monotonic v0.1 taint floor; only a new SecuritySession clears it. */
  private taintFloor: DataProvenance | undefined;
  private ended = false;
  private readonly approvalControllers = new Set<AbortController>();
  private readonly approvalGrants = new Map<
    string,
    { readonly policyHash: string; readonly riskState: RiskState }
  >();
  /**
   * Authorizations minted by this session. A structural brand alone is not
   * sufficient authority: it must also have been issued by this session's
   * deterministic PRE_ACTION decision and is consumable exactly once.
   */
  private readonly issuedAuthorizations = new Map<Authorized, string>();
  private readonly approvedSecretSinks = new Set<string>();
  private readonly activeSecretResolvers = new Set<ScopedSecretResolver>();
  private activePostAction: ActivePostAction | undefined;
  private readonly unsubscribeEvents: () => void;

  private readonly listeners = new Map<keyof SessionEvents, Set<(event: unknown) => void>>();
  private readonly sensitiveEgressBindings = new Map<string, SensitiveEgressBinding[]>();
  private readonly sourceSinkCheck: SourceSinkCheck;
  private readonly evaluatedNetworkMutations = new WeakSet<NetworkMutation>();

  constructor(init: SecuritySessionInit) {
    this.id = init.id;
    this.adapter = init.adapter;
    this.contract = init.contract;
    this.envelope = init.envelope;
    this.policy = init.policy;
    this.registry = init.registry;
    this.redactor = init.redactor;
    this.limits = init.limits;
    this.guardModel = init.guardModel;
    this.vault = init.vault;
    this.vaultAccess = init.vaultAccess;
    this.approvalHandler = init.approvalHandler;
    this.trace = init.trace;
    Object.defineProperty(this, STAGEHAND_EXECUTION, {
      enumerable: false,
      value: (authorized: Authorized, executor: ExactActionExecutor) =>
        this.executeIssuedAuthorization(authorized, () => executor.execute(), "unavailable"),
    });
    this.clock = init.clock ?? systemSessionClock;
    this.budgets = new SessionBudgetLedger(init.contract.budgets, this.clock.now(), this.clock);
    this.sourceSinkCheck = createSourceSinkCheck({
      isDestinationAllowed: (fingerprint, destinationOrigin, sink, fieldType) =>
        this.sensitiveEgressBindings
          .get(fingerprint)
          ?.some(
            (binding) =>
              binding.origins.has(destinationOrigin) &&
              binding.fieldTypes.has(sink === "typed_value" ? (fieldType ?? "") : sink),
          ) === true,
      limits: {
        ...DEFAULT_SOURCE_VALUE_LIMITS,
        ttlMs: Math.max(
          1,
          Math.min(
            DEFAULT_SOURCE_VALUE_LIMITS.ttlMs,
            init.contract.budgets?.maxDurationMs ?? DEFAULT_SOURCE_VALUE_LIMITS.ttlMs,
          ),
        ),
      },
      now: () => this.clock.now(),
    });
    this.memory = Object.freeze({
      guardWrite: (candidate: MemoryWriteCandidate, signal?: AbortSignal) =>
        this.guardMemoryWrite(candidate, signal),
      guardRead: (item: unknown, signal?: AbortSignal) => this.guardMemoryRead(item, signal),
    });
    const sink: AdapterEventSink = {
      onNavigation: (event) => this.recordAdapterEvent(event),
      onPopup: (event) => this.recordAdapterEvent(event),
      onDownload: (event) => this.recordAdapterEvent(event),
      onNetworkMutation: (mutation) => this.recordNetworkMutation(mutation),
      onEgressPayload: (payload, signal) => this.inspectEgress(payload, signal),
      onRouteRequest: (mutation, egressInspection) =>
        this.evaluateRouteRequest(mutation, egressInspection),
    };
    this.unsubscribeEvents = this.adapter.subscribe(this.id, sink);
  }

  get riskState(): RiskState {
    return this.risk;
  }

  get riskScore(): number {
    return this.score;
  }

  get policyEngine(): PolicyEngine {
    return this.policy;
  }

  get guardProvider(): GuardModelProvider | undefined {
    return this.guardModel;
  }

  /**
   * Dispatch one redacted guard request while atomically consuming the
   * session's call/token authority. A dispatched or cancelled attempt is never
   * refunded; composite providers reserve again before a fallback attempt.
   */
  async classifyWithGuard(
    request: GuardClassificationRequest,
    execution: SessionGuardExecution,
  ): Promise<GuardProviderOutcome> {
    if (this.ended || this.guardModel === undefined) {
      return { ok: false, kind: "unavailable" };
    }
    return runGuardProvider(this.guardModel, request, {
      signal: execution.signal,
      deadline: execution.deadline,
      maxInputBytes: execution.maxInputBytes ?? DEFAULT_GUARD_EXECUTION_LIMITS.maxInputBytes,
      maxOutputBytes: execution.maxOutputBytes ?? DEFAULT_GUARD_EXECUTION_LIMITS.maxOutputBytes,
      maxTokens: execution.maxTokens ?? DEFAULT_GUARD_EXECUTION_LIMITS.maxTokens,
      reserveDispatch: ({ calls, tokens }) =>
        this.reserveBudget([
          { kind: "guardCalls", amount: calls },
          { kind: "guardTokens", amount: tokens },
        ]),
    });
  }

  get sessionRisk(): SessionRisk {
    return { state: this.risk, score: this.score };
  }

  /** The redacted source metadata that established the current taint floor. */
  get sessionTaintFloor(): DataProvenance | undefined {
    return this.taintFloor;
  }

  /**
   * Register an application-supplied value with this session's vault. The raw
   * value is immediately added to the session redaction registry; callers only
   * receive an opaque handle (ADR-0005).
   */
  async registerSecret(
    name: string,
    value: string,
    kind: SecretHandle["kind"] = "SECRET",
  ): Promise<SecretHandle> {
    if (this.ended) throw new Error("session has ended");
    if (this.vault === undefined) throw new Error("no vault is configured for this session");
    const provenance: DataProvenance = { trust: "application", timestamp: nowIso(this.clock) };
    if (!this.redactor.registerSecret(value)) {
      throw new RangeError("redaction registry capacity exceeded");
    }
    if (!this.registerSourceValue(value, provenance)) {
      throw new RangeError("source value registry capacity exceeded");
    }
    const handle = await this.vault.store(name, value, kind);
    this.registerSensitiveBindings(value, handle);
    return handle;
  }

  private async guardMemoryWrite(input: unknown, signal?: AbortSignal): Promise<MemoryWriteResult> {
    const candidate = validateMemoryWriteCandidate(input);
    if (this.ended || signal?.aborted === true || candidate === null) {
      const reason: MemoryGuardReason =
        candidate === null
          ? memoryWriteCandidateExceedsBounds(input)
            ? "memory_bounds_exceeded"
            : "memory_item_invalid"
          : "memory_write_denied";
      this.trace.append("memory_write", { allowed: false, reasons: [reason] });
      return Object.freeze({ allowed: false, findings: [], reasons: [reason] });
    }

    const baseContext = this.buildContext("PERSISTENCE", {
      kind: "memoryCandidate",
      candidate: { value: candidate.content, provenance: candidate.provenance },
    });
    const phase = await runPhase(
      this.registry,
      "PERSISTENCE",
      signal === undefined ? baseContext : { ...baseContext, signal },
      this.limits,
    );
    this.recordTierMetrics("PERSISTENCE", phase.tierMetrics);
    const findings = phase.results.flatMap((result) => result.findings);
    for (const result of phase.results) {
      this.trace.append("scan_result", {
        scanner: result.scanner,
        verdict: result.verdict,
        severity: result.severity,
      });
      for (const finding of result.findings) {
        this.trace.append("finding", {
          id: finding.id,
          category: finding.category,
          sourceType: finding.source.type,
          evidenceHash: hash(finding.evidence),
          provenance: finding.provenance,
        });
      }
    }

    const completedRequiredDetectors = new Set(phase.results.map((result) => result.scanner));
    const incomplete =
      isAbortSignalAborted(signal) ||
      phase.failures.length > 0 ||
      phase.oversized ||
      !completedRequiredDetectors.has("memory-write") ||
      !completedRequiredDetectors.has("secret-sensitive") ||
      phase.results.some(
        (result) => result.verdict === "block" || result.metadata?.["failureKind"] !== undefined,
      );
    if (incomplete) {
      const reason: MemoryGuardReason = "memory_scan_incomplete";
      this.trace.append("memory_write", {
        allowed: false,
        reasons: [reason],
        findingCount: findings.length,
        provenance: candidate.provenance,
      });
      return Object.freeze({ allowed: false, findings, reasons: [reason] });
    }

    const materializedSpans = await this.materializeSensitiveSpans(
      candidate.content,
      phase.sanitizationSpans,
    );
    const content = this.redactor.redact(
      applySanitizationPipeline(candidate.content, materializedSpans, phase.sanitizedTexts),
    );
    const markers = memoryMarkers(findings);
    const sensitivity = findings.some((finding) => finding.category === "secret_detected")
      ? "secret"
      : markers.length > 0
        ? "sensitive"
        : "none";
    const item = createStoredMemoryItem({
      content,
      provenance: candidate.provenance,
      sensitivity,
      markers,
    });
    this.trace.append("memory_write", {
      allowed: true,
      contentHash: item.contentHash,
      sensitivity: item.sensitivity,
      markers: item.markers,
      findingCount: findings.length,
      provenance: item.provenance,
    });
    return Object.freeze({ allowed: true, item, findings, reasons: [] });
  }

  private guardMemoryRead(input: unknown, signal?: AbortSignal): UntrustedContent {
    if (this.ended || signal?.aborted === true) {
      this.trace.append("memory_read", { allowed: false, reasons: ["memory_read_denied"] });
      throw new MemoryGuardError("memory_read_denied");
    }
    const shaped = validateStoredMemoryItemShape(input);
    if (shaped === null) {
      this.trace.append("memory_read", { allowed: false, reasons: ["memory_item_invalid"] });
      throw new MemoryGuardError("memory_item_invalid");
    }
    if (memoryItemHash(shaped) !== shaped.contentHash) {
      this.trace.append("memory_read", {
        allowed: false,
        reasons: ["memory_content_hash_mismatch"],
      });
      throw new MemoryGuardError("memory_content_hash_mismatch");
    }
    const datum = memoryReadDatum(shaped);
    this.registerSourceValue(shaped.content, shaped.provenance, signal);
    this.registerSourceOriginBinding(shaped.content, shaped.provenance);
    this.releaseUntrustedContext(shaped.provenance, "memory_read");
    const released = wrapUntrustedContent({ content: datum.value, provenance: datum.provenance });
    this.trace.append("memory_read", {
      allowed: true,
      contentHash: shaped.contentHash,
      sensitivity: shaped.sensitivity,
      markers: shaped.markers,
      storedProvenance: shaped.provenance,
      releasedProvenance: released.provenance,
    });
    return released;
  }

  on<K extends keyof SessionEvents>(
    type: K,
    listener: (event: SessionEvents[K]) => void,
  ): () => void {
    let set = this.listeners.get(type);
    if (set === undefined) {
      set = new Set();
      this.listeners.set(type, set);
    }
    const wrapped = listener as (event: unknown) => void;
    set.add(wrapped);
    return () => {
      set.delete(wrapped);
    };
  }

  /** Update the risk state (monotonic) and emit/trace the change. */
  setRisk(state: RiskState, score: number, signal?: RiskSignal): void {
    const previousState = this.risk;
    const nextState = maxRiskState(this.risk, state);
    const nextScore = Math.max(this.score, score);
    if (this.risk !== nextState || this.score !== nextScore) {
      this.risk = nextState;
      this.score = nextScore;
      this.emit("riskChanged", this.sessionRisk);
      this.trace.append("risk_change", {
        state: nextState,
        score: nextScore,
        previousState,
        ...(signal !== undefined ? { signal } : {}),
      });
    }
  }

  recordDecision(
    action: CanonicalAction,
    verdict: AggregateVerdict,
    reasons: readonly string[],
    policyHash: string,
    evidence: readonly EvidenceReference[] = [],
    matchedRules: readonly string[] = [],
    appliedSuppressions: readonly {
      readonly rule: string;
      readonly scope: string;
      readonly justification: string;
    }[] = [],
  ): SessionDecision {
    // The decision's action is redacted so raw secret values never leave the
    // session (INV-05); secret handles pass through unchanged.
    const decision: SessionDecision = {
      verdict,
      reasons,
      // Adapter operation payloads can contain file bytes. They are needed only
      // at the exact executor boundary and must never enter decisions/events.
      action: redactDeep(withoutRawOperation(action), this.redactor) as CanonicalAction,
      ...(evidence.length > 0 ? { evidence } : {}),
      ...(matchedRules.length > 0 ? { matchedRules } : {}),
      ...(appliedSuppressions.length > 0 ? { appliedSuppressions } : {}),
    };
    this.trace.append("policy_decision", {
      verdict,
      reasons,
      policyHash,
      ...(matchedRules.length > 0 ? { matchedRules } : {}),
      ...(appliedSuppressions.length > 0 ? { appliedSuppressions } : {}),
      ...(evidence.length > 0 ? { evidence } : {}),
    });
    this.emit("decision", decision);
    return decision;
  }

  /**
   * Capture and scan the current page (PERCEPTION phase). Returns the
   * sanitized representation offered to the agent plus findings and the
   * aggregated assessment; updates the session risk state.
   */
  async observe(): Promise<PerceptionResult> {
    const result = await this.observeForAuthorization();
    this.releaseUntrustedContext(result.sanitizedText.provenance, "observation");
    return { ...result, observation: redactPublicObservation(result.observation, this.redactor) };
  }

  /**
   * Capture page state for firewall authorization without handing page content
   * to an agent. Adapter wrappers must use this rather than `observe()` so an
   * internal reobservation does not incorrectly become an agent-context
   * release.
   */
  async observeForAuthorization(): Promise<PerceptionResult> {
    const observation = await this.adapter.observe();
    this.currentOrigin = observation.origin;
    const ctx = this.buildContext("PERCEPTION", { kind: "observation", observation });
    const phase = await runPhase(this.registry, "PERCEPTION", ctx, this.limits);
    this.recordTierMetrics("PERCEPTION", phase.tierMetrics);
    this.updateRequiredGuardAvailability(phase);

    const findings = phase.results
      .flatMap((r) => r.findings)
      .map((finding) => redactFinding(finding, this.redactor));
    const baseText = observationText(observation);
    const materializedSpans = await this.materializeSensitiveSpans(
      baseText,
      phase.sanitizationSpans,
    );
    const sanitizedText = this.redactor.redact(
      applySanitizationPipeline(baseText, materializedSpans, phase.sanitizedTexts),
    );
    const sanitizedProvenance = provenanceAfterSanitization(observation.provenance, phase);

    const assessment = riskAggregator.aggregate({
      scanResults: phase.results.map((result) => ({
        ...result,
        findings: result.findings.map((finding) => redactFinding(finding, this.redactor)),
      })),
      policyDecision: { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "perception" },
      riskState: this.risk,
      score: this.score,
      budgetsExhausted: false,
    });

    this.trace.append("observation", {
      url: observation.url,
      origin: observation.origin,
      provenance: observation.provenance,
    });
    for (const failure of phase.failures) {
      this.trace.append("scan_result", { scanner: failure.scanner, failureKind: failure.kind });
    }
    for (const finding of findings) {
      this.trace.append("finding", {
        id: finding.id,
        category: finding.category,
        sourceType: finding.source.type,
        evidenceHash: hash(finding.evidence),
        provenance: finding.provenance,
      });
      this.emit("finding", finding);
    }

    // Minimal risk rule (OAF-SEC-006 minimal form, used by the M2 slice): a
    // high-severity injection finding restricts the session.
    const injectionFinding = [...assessment.deterministic, ...assessment.provenance].find(
      (f) =>
        (f.severity === "high" || f.severity === "critical") &&
        (f.recommendedAction === "block" ||
          f.category.includes("hidden_dom") ||
          f.category.includes("injection") ||
          f.category.includes("instruction")),
    );
    let verdict = assessment.verdict;
    if (injectionFinding !== undefined) {
      this.applyRiskSignal(
        injectionFinding.severity === "critical" ? "critical_finding" : "high_confidence_injection",
      );
      verdict = "RESTRICT";
    } else if (
      assessment.deterministic.some(
        (finding) =>
          finding.category === "encoded_payload_limit" ||
          finding.category === "scanner_unavailable",
      )
    ) {
      // An incomplete deterministic perception pass is low-confidence
      // evidence, not a clean observation. Preserve WARN as the assessment,
      // but monotonically restrict the session before later side effects.
      this.applyRiskSignal("hidden_injection");
    }

    return {
      observation,
      sanitizedText: provenanced(sanitizedText, sanitizedProvenance),
      findings,
      assessment: { ...assessment, verdict },
    };
  }

  /** Record a firewall-observed risk signal. Signals can only narrow a session. */
  applyRiskSignal(signal: RiskSignal): void {
    const transition = applyRiskSignal(this.sessionRisk, signal);
    this.setRisk(transition.current.state, transition.current.score, signal);
  }

  /**
   * Application-facing reservation hook for adapter/provider consumers. It
   * only narrows future authority and records an exhaustion before callers can
   * attempt a side effect. Direct browser data never controls this API.
   */
  reserveBudget(uses: readonly BudgetUse[]): boolean {
    const reserved = this.budgets.tryConsumeAll(uses);
    if (!reserved) {
      this.trace.append("budget_event", {
        budget: uses.map((use) => use.kind).join(","),
        remaining: 0,
      });
    }
    return reserved;
  }

  /**
   * Record bounded, adapter-derived outcome metadata after the action boundary.
   * Adapters must not provide response bodies or page-controlled raw payloads.
   */
  recordPostAction(
    type: CanonicalAction["type"],
    metadata: Readonly<Record<string, unknown>>,
  ): void {
    if (this.ended) return;
    this.trace.append("post_action", {
      type,
      metadata: redactDeep(metadata, this.redactor),
    });
  }

  /** Explicit application release; navigation and page events can never lower risk. */
  releaseQuarantine(): boolean {
    if (this.risk !== "QUARANTINED" || this.ended) return false;
    const previousState = this.risk;
    this.risk = "NORMAL";
    this.score = 0;
    this.emit("riskChanged", this.sessionRisk);
    this.trace.append("risk_change", {
      state: this.risk,
      score: this.score,
      previousState,
      release: "application",
    });
    return true;
  }

  /**
   * Authorize a proposed action (PRE_ACTION phase + policy + risk). Unknown or
   * out-of-envelope actions fail closed; high-impact actions are denied in
   * restricted risk states with `session_restricted`.
   */
  async authorize(action: CanonicalAction): Promise<SessionDecision> {
    return this.authorizePrepared(this.prepareAction(action));
  }

  /**
   * Authorize a batch of application-submitted actions. `instructedBy: user`
   * is a TB1-only assertion, recorded before use, and still traverses the full
   * deterministic authorization pipeline.
   */
  async authorizeActions(
    actions: readonly CanonicalAction[],
    options: TrustedInstructionOptions = {},
  ): Promise<readonly SessionDecision[]> {
    return Promise.all(
      actions.map((action) => {
        const prepared = this.prepareAction(action, options);
        if (options.instructedBy === "user") {
          this.trace.append("trusted_instruction_claim", {
            instructedBy: "user",
            actionType: prepared.type,
            instructionProvenance: prepared.instructionProvenance,
          });
        }
        return this.authorizePrepared(prepared);
      }),
    );
  }

  private async authorizePrepared(
    action: CanonicalAction,
    intent?: ActionIntent,
  ): Promise<SessionDecision> {
    this.trace.append("proposed_action", {
      type: action.type,
      instructionProvenance: action.instructionProvenance,
      ...(action.data !== undefined ? { dataProvenance: action.data.provenance } : {}),
    });
    this.trace.append("canonical_action", {
      type: action.type,
      instructionProvenance: action.instructionProvenance,
      ...(action.data !== undefined ? { dataProvenance: action.data.provenance } : {}),
      ...helperTraceMetadata(action),
    });

    const egress = await this.actionEgressEvaluation(action, intent);
    const exfiltrationReasons = this.crossOriginExfiltrationReasons(action, egress);
    const builtInReasons = uniqueReasons([
      ...(this.requiredGuardUnavailable && isHighImpact(action)
        ? [REASON_CODES.scanner_unavailable]
        : []),
      ...this.unboundHandleReasons(action),
      ...this.untrustedNavigationReasons(action),
      ...egress.reasons,
      ...exfiltrationReasons,
    ]);
    if (builtInReasons.length > 0) {
      if (
        exfiltrationReasons.length > 0 ||
        egress.reasons.includes(REASON_CODES.sensitive_value_in_egress)
      ) {
        this.applyRiskSignal("secret_requested");
      }
      const riskAction = this.evaluateRiskAction(action);
      return this.recordDecision(
        action,
        "BLOCK",
        riskAction === "block"
          ? appendReason(builtInReasons, REASON_CODES.session_restricted)
          : builtInReasons,
        this.policy.policyHash,
      );
    }

    // PRE_ACTION scanners run after immutable built-ins and before policy,
    // budgets, and risk. Required deterministic failure is then aggregated as
    // a final block; a scanner can never be bypassed by a later policy allow.
    const ctx = this.buildContext("PRE_ACTION", { kind: "proposedAction", action });
    const phase = await runPhase(this.registry, "PRE_ACTION", ctx, this.limits);
    this.recordTierMetrics("PRE_ACTION", phase.tierMetrics);
    for (const result of phase.results) {
      this.trace.append("scan_result", {
        scanner: result.scanner,
        verdict: result.verdict,
        severity: result.severity,
      });
      for (const finding of result.findings) {
        this.trace.append("finding", {
          id: finding.id,
          category: finding.category,
          sourceType: finding.source.type,
          evidenceHash: hash(finding.evidence),
          provenance: finding.provenance,
        });
      }
    }
    for (const failure of phase.failures) {
      this.trace.append("scan_result", { scanner: failure.scanner, failureKind: failure.kind });
    }

    let policyDecision = this.policy.evaluate({
      action,
      envelope: this.envelope,
      riskState: this.risk,
      runtimeState: this.budgets.runtimeState(),
    });
    const budgetUses = budgetUsesFor(action);
    if (!this.reserveBudget(budgetUses)) {
      policyDecision = {
        ...policyDecision,
        // Budget exhaustion can only narrow a decision. In particular, an
        // existing deterministic policy block must never become approvable.
        verdict:
          policyDecision.verdict === "BLOCK"
            ? "BLOCK"
            : isHighImpact(action)
              ? "REQUIRE_APPROVAL"
              : "BLOCK",
        reasons: appendReason(policyDecision.reasons, REASON_CODES.budget_exceeded),
      };
    }
    const riskAction = this.evaluateRiskAction(action);
    if (riskAction === "block") {
      policyDecision = {
        ...policyDecision,
        verdict: "BLOCK",
        reasons: appendReason(policyDecision.reasons, REASON_CODES.session_restricted),
      };
    } else if (riskAction === "require_approval" && policyDecision.verdict === "ALLOW") {
      policyDecision = {
        ...policyDecision,
        verdict: "REQUIRE_APPROVAL",
        reasons: [...policyDecision.reasons, REASON_CODES.approval_required],
        requiredApproval: true,
      };
    }

    const assessment = riskAggregator.aggregate({
      scanResults: phase.results,
      policyDecision,
      riskState: this.risk,
      score: this.score,
      budgetsExhausted: false,
      restrictedActionAllowed: riskAction === "allow",
    });

    let verdict = assessment.verdict;
    const reasons: string[] = [...assessment.reasons];
    const sessionGrant = this.hasSessionApprovalGrant(
      action,
      policyDecision,
      assessment.decidedBy?.layer,
    );
    if (sessionGrant) {
      verdict = "ALLOW";
      reasons.length = 0;
    } else if (verdict === "REQUIRE_APPROVAL") {
      const approvalState = this.approvalState(action);
      const approval = await this.requestApproval(action, [
        ...assessment.deterministic,
        ...assessment.semantic,
      ]);
      if (!approval.approved) {
        verdict = "BLOCK";
        reasons.push(approval.reason ?? REASON_CODES.approval_denied);
      } else if (!this.approvalStateMatches(action, approvalState)) {
        // A human decision binds only the firewall-owned state that was shown
        // to the handler. Any action, policy, risk, budget, or session change
        // invalidates it; the caller must submit the action again (INV-12/19).
        verdict = "BLOCK";
        reasons.push(REASON_CODES.approval_reauthorization_required);
      } else {
        if (
          approval.scope === "session" &&
          policyDecision.verdict === "REQUIRE_APPROVAL" &&
          assessment.decidedBy?.layer === "policy" &&
          !policyDecision.reasons.includes(REASON_CODES.budget_exceeded) &&
          riskAction === "allow"
        ) {
          this.approvalGrants.set(approvalGrantKey(action), {
            policyHash: this.policy.policyHash,
            riskState: this.risk,
          });
        }
        verdict = "ALLOW";
        reasons.length = 0;
      }
    }

    const evidence = evidenceReferences([
      ...assessment.deterministic,
      ...assessment.semantic,
      ...assessment.provenance,
    ]);
    return this.recordDecision(
      action,
      verdict,
      reasons,
      policyDecision.policyHash,
      evidence,
      policyDecision.matchedRules,
      policyDecision.appliedSuppressions,
    );
  }

  /**
   * Authorize an action and mint its branded, state-bound executor input.
   * The adapter supplies an immutable snapshot; core owns the decision and
   * trace identity so a wrapper cannot fabricate authorization evidence.
   */
  async authorizeBound(
    action: CanonicalAction,
    intent: ActionIntent,
  ): Promise<BoundAuthorizationResult> {
    if (stableSerialize(intent.action) !== stableSerialize(action)) {
      throw new TypeError("ActionIntent action does not match the action being authorized");
    }
    const preparedAction = this.prepareAction(action);
    // Provenance is authorization-relevant state. A floor may activate after a
    // wrapper built its intent, so bind the exact effective action rather than
    // allowing the application-labelled candidate to reach the executor.
    const preparedIntent: ActionIntent = { ...intent, action: preparedAction };
    if (preparedIntent.policyHash !== this.policy.policyHash || isIntentExpired(preparedIntent)) {
      const reason =
        preparedIntent.policyHash !== this.policy.policyHash
          ? REASON_CODES.action_policy_mismatch
          : REASON_CODES.action_intent_expired;
      const decision = this.recordDecision(
        preparedAction,
        "BLOCK",
        [reason],
        this.policy.policyHash,
      );
      this.trace.append("action_revalidation", { reason, intentId: preparedIntent.intentId });
      return { decision };
    }
    const decision = await this.authorizePrepared(preparedAction, preparedIntent);
    if (decision.verdict !== "ALLOW") {
      return { decision };
    }
    const decisionId = randomBytes(8).toString("hex");
    const authorized = mintAuthorizedAction({
      action: preparedAction,
      intent: preparedIntent,
      operationHash: preparedIntent.operationHash,
      policyHash: this.policy.policyHash,
      decisionId,
      traceId: decisionId,
    });
    this.trace.append("authorized_action", { intentId: preparedIntent.intentId, decisionId });
    // Bind the authorization to every firewall-owned input that can change
    // between decision and side effect: policy, risk, budget, grants, action
    // identity, and session liveness. This snapshot deliberately excludes
    // wall-clock churn; expiry is checked independently below.
    this.issuedAuthorizations.set(authorized, this.approvalState(preparedAction));
    return { decision, authorized };
  }

  /** Execute only a core-minted authorization through the adapter boundary. */
  async executeAuthorized(authorized: Authorized): Promise<unknown> {
    return this.executeIssuedAuthorization(authorized, async (issuedState) => {
      const resolver = this.createSecretResolver(authorized, issuedState);
      if (resolver === undefined) {
        return this.adapter.executeAuthorized(authorized, denyAllResolver);
      }
      this.activeSecretResolvers.add(resolver);
      try {
        const result = await this.adapter.executeAuthorized(authorized, resolver);
        resolver.commit();
        return result;
      } finally {
        resolver.revoke();
        this.activeSecretResolvers.delete(resolver);
      }
    });
  }

  private async executeIssuedAuthorization(
    authorized: Authorized,
    execute: (issuedState: string) => Promise<unknown>,
    postActionStatus?: PostActionStatus,
  ): Promise<unknown> {
    if (this.ended) throw new TypeError("cannot execute an authorization after session end");
    const issuedState = this.issuedAuthorizations.get(authorized);
    if (issuedState === undefined) {
      throw new TypeError("authorization was not issued by this session or was already used");
    }
    const reason = isIntentExpired(authorized.intent)
      ? REASON_CODES.action_intent_expired
      : authorized.policyHash !== this.policy.policyHash
        ? REASON_CODES.action_policy_mismatch
        : !this.approvalStateMatches(authorized.action, issuedState)
          ? REASON_CODES.approval_reauthorization_required
          : undefined;
    if (reason !== undefined) {
      this.issuedAuthorizations.delete(authorized);
      this.recordRevalidation(reason, authorized.intent.intentId);
      throw new TypeError(`authorization requires full reauthorization (${reason})`);
    }
    // Consume before any framework call. A retry must mint a new decision and
    // can never patch or replay this authority.
    this.issuedAuthorizations.delete(authorized);
    if (this.activePostAction !== undefined) {
      throw new TypeError("only one post-action observation window may be active per session");
    }
    const active: ActivePostAction = {
      action: authorized.action,
      intent: authorized.intent,
      startedOrigin: authorized.intent.target.origin ?? authorized.action.target?.origin,
      events: [],
      status:
        postActionStatus ??
        (postActionCapabilitiesAvailable(this.adapter.capabilities) ? "complete" : "unavailable"),
    };
    this.activePostAction = active;
    try {
      try {
        const result = await execute(issuedState);
        this.trace.append("execution", {
          intentId: authorized.intent.intentId,
          type: authorized.action.type,
        });
        return redactDeep(result, this.redactor);
      } catch (error: unknown) {
        if (isSafeRevalidationError(error, this.redactor)) throw error;
        throw new TypeError("authorized execution failed");
      }
    } finally {
      await this.completePostAction(active);
    }
  }

  /** Record an adapter's deterministic pre-execution invalidation. */
  recordRevalidation(reason: ReasonCode, intentId: string): void {
    this.trace.append("action_revalidation", { reason, intentId });
  }

  /**
   * Bound and scan adapter-derived text before returning it to application or
   * agent code. The result remains web provenance and never becomes authority.
   */
  async inspectUntrustedText(
    content: string,
    maxBytes = 65_536,
    provenance: DataProvenance = { trust: "web", timestamp: new Date().toISOString() },
  ): Promise<UntrustedContent> {
    if (Buffer.byteLength(content, "utf8") > maxBytes) {
      throw new RangeError("untrusted adapter output exceeds the configured byte limit");
    }
    const ctx = this.buildContext("MODEL_OUTPUT", {
      kind: "modelOutput",
      output: { content, provenance },
    });
    const phase = await runPhase(this.registry, "MODEL_OUTPUT", ctx, this.limits);
    this.recordTierMetrics("MODEL_OUTPUT", phase.tierMetrics);
    this.updateRequiredGuardAvailability(phase);
    if (phase.failures.length > 0) {
      throw new Error(REASON_CODES.scanner_unavailable);
    }
    const materializedSpans = await this.materializeSensitiveSpans(
      content,
      phase.sanitizationSpans,
    );
    const sanitized = this.redactor.redact(
      applySanitizationPipeline(content, materializedSpans, phase.sanitizedTexts),
    );
    this.registerSourceValue(sanitized, provenance);
    this.registerSourceOriginBinding(sanitized, provenance);
    this.releaseUntrustedContext(provenance, "tool_output");
    return wrapUntrustedContent({ content: sanitized, provenance });
  }

  private async materializeSensitiveSpans(
    base: string,
    spans: readonly SanitizationSpan[],
  ): Promise<readonly SanitizationSpan[]> {
    const output: SanitizationSpan[] = [];
    for (const span of spans) {
      const marker = /^\[\[OAF_SENSITIVE:(SECRET|PII|CREDENTIAL):([a-z0-9_.-]{1,64})\]\]$/.exec(
        span.replacement,
      );
      if (marker === null) {
        output.push(span);
        continue;
      }
      const value = base.slice(span.start, span.end);
      if (value.length === 0) {
        output.push({ ...span, replacement: "[REDACTED:SENSITIVE]" });
        continue;
      }
      this.redactor.registerSecret(value);
      this.registerSourceValue(value, span.provenance);
      this.registerSourceOriginBinding(value, span.provenance);
      if (this.vault === undefined) {
        output.push({ ...span, replacement: "[REDACTED:SENSITIVE]" });
        continue;
      }
      try {
        const pattern = marker[2] ?? "detected";
        const kind = marker[1] as SecretHandle["kind"];
        const handle = await this.vault.store(
          `detected_${pattern}_${hash(value).slice(0, 8)}`,
          value,
          kind,
        );
        this.registerSensitiveBindings(value, handle);
        output.push({ ...span, replacement: serializeHandle(handle) });
      } catch {
        // Capacity/expiry errors fail closed: never release the matched value.
        output.push({ ...span, replacement: "[REDACTED:SENSITIVE]" });
      }
    }
    return output;
  }

  /** Resolve an approval for an action; deny-by-default (INV-11). */
  async requestApproval(
    action: CanonicalAction,
    findings: readonly Finding[],
  ): Promise<ApprovalDecision> {
    if (this.ended)
      return { approved: false, scope: "once", reason: REASON_CODES.approval_cancelled };
    const timeoutMs = this.contract.approval?.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;
    // Approval requests never expose raw secrets (INV-05): the action data and
    // finding text are redacted before the request reaches the handler or the
    // event stream. Secret values still resolve executor-side for bound sinks.
    const request: ApprovalRequest = {
      id: randomBytes(6).toString("hex"),
      sessionId: this.id,
      action: sanitizeApprovalAction(action, this.redactor),
      findings: sanitizeApprovalFindings(findings, this.redactor),
      risk: this.sessionRisk,
      expiresAt: new Date(this.clock.now() + timeoutMs).toISOString(),
    };
    this.trace.append("approval_request", {
      id: request.id,
      actionType: action.type,
      risk: this.risk,
      expiresAt: request.expiresAt,
    });
    this.emit("approvalRequired", request);
    const controller = new AbortController();
    this.approvalControllers.add(controller);
    const decision = await resolveApproval(this.approvalHandler, request, {
      now: () => this.clock.now(),
      signal: controller.signal,
    });
    this.approvalControllers.delete(controller);
    this.trace.append("approval_decision", {
      id: request.id,
      approved: decision.approved,
      scope: decision.scope,
      ...(decision.reason !== undefined ? { reason: decision.reason } : {}),
    });
    return decision;
  }

  get unsafe(): { rawPage(reason: string): unknown } {
    const adapter = this.adapter;
    const trace = this.trace;
    const redactor = this.redactor;
    const rawAdapterAccess = this.rawAdapterAccess;
    return {
      rawPage(reason: string): unknown {
        if (typeof reason !== "string" || reason.trim().length === 0) {
          throw new TypeError("unsafe.rawPage requires a non-empty reason");
        }
        // Recorded before raw-handle access (INV-18), with the caller reason
        // redacted so a secret-bearing reason never reaches the trace.
        trace.append("escape_hatch", { reason: redactor.redact(reason) });
        return adapter.rawPage(rawAdapterAccess);
      },
    };
  }

  /** End the session: flush the trace, invalidate handles, record final state. */
  async end(): Promise<TraceDocument> {
    if (this.ended) {
      return this.trace.document();
    }
    this.ended = true;
    if (this.activePostAction !== undefined) this.activePostAction.status = "cancelled";
    for (const controller of this.approvalControllers) controller.abort();
    this.approvalControllers.clear();
    this.issuedAuthorizations.clear();
    this.approvalGrants.clear();
    for (const resolver of this.activeSecretResolvers) resolver.revoke();
    this.activeSecretResolvers.clear();
    this.approvedSecretSinks.clear();
    this.sensitiveEgressBindings.clear();
    this.sourceSinkCheck.clear();
    this.unsubscribeEvents();
    this.trace.append("session_end", { risk: this.risk, score: this.score });
    if (this.vault !== undefined) {
      await this.vault.invalidateSession();
    }
    const document = this.trace.document();
    this.redactor.clear();
    return document;
  }

  private recordTierMetrics(phase: SecurityPhase, metrics: readonly PhaseTierMetric[]): void {
    for (const metric of metrics) {
      this.trace.append("scan_result", {
        phase,
        tier: metric.tier,
        status: metric.status,
        scannerCount: metric.scannerCount,
        ...(metric.skipReason !== undefined ? { skipReason: metric.skipReason } : {}),
      });
    }
  }

  private updateRequiredGuardAvailability(phase: {
    readonly requiredGuardChecked: boolean;
    readonly requiredGuardFailure: boolean;
  }): void {
    if (phase.requiredGuardChecked) {
      this.requiredGuardUnavailable = phase.requiredGuardFailure;
    }
  }

  private buildContext(phase: SecurityPhase, payload: PhasePayload): SecurityContext {
    return {
      phase,
      sessionId: this.id,
      taskContract: this.contract,
      envelope: this.envelope,
      riskState: this.risk,
      payload,
      provenance: provenanceOf(payload),
      redactor: this.redactor,
      deadline: Date.now() + this.limits.phaseDeadlineMs,
      signal: new AbortController().signal,
    };
  }

  private emit<K extends keyof SessionEvents>(type: K, event: SessionEvents[K]): void {
    const set = this.listeners.get(type);
    if (set === undefined) {
      return;
    }
    // Every public event passes through the redaction boundary (INV-05);
    // registering a custom listener never bypasses redaction.
    const redacted = redactDeep(event, this.redactor) as SessionEvents[K];
    for (const listener of set) {
      listener(redacted);
    }
  }

  private capturePostActionEvent(event: AdapterEvent): void {
    const active = this.activePostAction;
    if (active === undefined || active.status !== "complete") return;
    const rootPageId = active.intent.observation.pageId;
    const relevant =
      event.kind === "popup" ||
      (event.pageId === rootPageId && (event.kind !== "navigation" || event.mainFrame === true));
    if (!relevant) return;
    if (active.events.length >= POST_ACTION_MAX_EVENTS) {
      active.status = "overflow";
      return;
    }
    active.events.push(Object.freeze({ ...event }));
  }

  private async completePostAction(active: ActivePostAction): Promise<void> {
    if (this.activePostAction !== active) return;
    try {
      if (active.status === "complete") {
        await new Promise<void>((resolve) => setTimeout(resolve, POST_ACTION_SETTLE_MS));
      }
      if (this.ended) active.status = "cancelled";
      const observation: PostActionObservation = Object.freeze({
        intentId: active.intent.intentId,
        action: active.action,
        intent: active.intent,
        ...(active.startedOrigin !== undefined ? { startedOrigin: active.startedOrigin } : {}),
        events: Object.freeze([...active.events]),
        status: active.status,
      });
      const reasons: string[] = [...comparePostAction(observation)];
      const phase = await runPhase(
        this.registry,
        "POST_ACTION",
        this.buildContext("POST_ACTION", { kind: "postAction", observation }),
        this.limits,
      );
      this.recordTierMetrics("POST_ACTION", phase.tierMetrics);
      for (const result of phase.results) {
        this.trace.append("scan_result", {
          scanner: result.scanner,
          verdict: result.verdict,
          severity: result.severity,
        });
        for (const finding of result.findings) {
          this.trace.append("finding", {
            id: finding.id,
            category: finding.category,
            sourceType: finding.source.type,
            evidenceHash: hash(finding.evidence),
          });
          this.emit("finding", finding);
        }
      }
      if (phase.failures.length > 0) reasons.push(REASON_CODES.scanner_unavailable);
      this.trace.append("post_action", {
        intentId: observation.intentId,
        status: observation.status,
        eventCount: observation.events.length,
        ...(reasons.length > 0 ? { reasons } : {}),
      });
      for (const reason of reasons) this.applyPostActionRisk(reason);
    } finally {
      if (this.activePostAction === active) this.activePostAction = undefined;
    }
  }

  private applyPostActionRisk(reason: string): void {
    switch (reason) {
      case REASON_CODES.unexpected_redirect:
      case REASON_CODES.unexpected_origin_change:
        this.applyRiskSignal("cross_origin_redirect");
        return;
      case REASON_CODES.unexpected_tab:
        this.applyRiskSignal("unrelated_tab");
        return;
      case REASON_CODES.unexpected_download:
        this.applyRiskSignal("unexpected_download");
        return;
      case REASON_CODES.post_action_observation_unavailable:
      case REASON_CODES.post_action_observation_cancelled:
      case REASON_CODES.post_action_observation_overflow:
      case REASON_CODES.scanner_unavailable:
        this.setRisk("RESTRICTED", Math.max(this.score, 40));
        return;
    }
  }

  private recordAdapterEvent(event: AdapterEvent): boolean {
    if (event.sessionId !== this.id || this.ended) return event.kind === "popup";
    this.trace.append("adapter_event", {
      kind: event.kind,
      ...(event.url !== undefined ? { url: event.url } : {}),
      ...(event.origin !== undefined ? { origin: event.origin } : {}),
      ...(event.pageId !== undefined ? { pageId: event.pageId } : {}),
      ...(event.frameId !== undefined ? { frameId: event.frameId } : {}),
      ...(event.revision !== undefined ? { revision: event.revision } : {}),
      ...(event.mainFrame !== undefined ? { mainFrame: event.mainFrame } : {}),
    });
    this.capturePostActionEvent(event);
    if (event.kind === "navigation" && event.mainFrame !== false && event.origin !== undefined) {
      this.currentOrigin = event.origin;
    }
    if (event.kind === "popup") {
      const tabBudget = this.reserveBudget([{ kind: "tabs" }]);
      if (!tabBudget) {
        // The adapter reports popups after browser creation. Quarantining is
        // the only safe deterministic containment available at this hook;
        // adapters with a pre-open hook must use it in their own later prompt.
        this.setRisk("QUARANTINED", this.score);
        return true;
      } else if (
        event.origin !== undefined &&
        this.currentOrigin !== undefined &&
        !sameSite(event.origin, this.currentOrigin)
      ) {
        this.applyRiskSignal("unrelated_tab");
      }
      if (event.url !== undefined) {
        const popupPolicy = this.envelope.evaluate({
          type: "NAVIGATE",
          destination: event.url,
          ...(this.currentOrigin !== undefined ? { target: { origin: this.currentOrigin } } : {}),
        });
        if (!popupPolicy.allowed) {
          this.setRisk("RESTRICTED", this.score);
          return true;
        }
      }
    }
    return false;
  }

  private recordNetworkMutation(mutation: NetworkMutation): void {
    if (this.ended) return;
    if (mutation.enforcement === "enforced" && this.evaluatedNetworkMutations.has(mutation)) return;
    const correlation = correlateNetworkMutation(
      mutation,
      mutation.actionIntentId === undefined ? undefined : this.activePostAction?.intent,
      this.clock.now(),
    );
    const decision = evaluateNetworkMutation({
      mutation,
      envelope: this.envelope,
      riskState: this.risk,
      destinationRules: this.policy.destinationRules ?? DEFAULT_DESTINATION_RULES,
      correlation,
    });
    this.trace.append("network_mutation", {
      surface: mutation.surface,
      initiator: mutation.initiator,
      destination: mutation.destination,
      enforcement: mutation.enforcement,
      provenance: mutation.provenance,
      verdict: decision.verdict,
      reasons: decision.reasons,
      correlation: correlation.status,
      ...(correlation.intentId !== undefined ? { intentId: correlation.intentId } : {}),
    });
    this.applyNetworkRisk(decision.reasons);
  }

  private async inspectEgress(
    payload: EgressPayload,
    signal?: AbortSignal,
  ): Promise<EgressInspection> {
    if (this.ended) {
      return {
        verdict: "block",
        reasons: [REASON_CODES.egress_inspection_incomplete],
        inspectedBytes: 0,
        matchCount: 0,
      };
    }
    const phaseContext = this.buildContext("EGRESS", {
      kind: "egressPayload",
      payload: { value: payload.value, provenance: payload.provenance },
    });
    const phase = await runPhase(
      this.registry,
      "EGRESS",
      signal === undefined ? phaseContext : { ...phaseContext, signal },
      this.limits,
    );
    this.recordTierMetrics("EGRESS", phase.tierMetrics);
    for (const result of phase.results) {
      this.trace.append("scan_result", {
        scanner: result.scanner,
        verdict: result.verdict,
        severity: result.severity,
      });
      for (const finding of result.findings) {
        this.trace.append("finding", {
          id: finding.id,
          category: finding.category,
          sourceType: finding.source.type,
          evidenceHash: hash(finding.evidence),
          provenance: finding.provenance,
        });
      }
    }
    for (const span of phase.sanitizationSpans) {
      if (!isSensitiveMarker(span.replacement)) continue;
      const value = payload.value.slice(span.start, span.end);
      if (value.length === 0) continue;
      this.redactor.registerSecret(value);
      this.registerSourceValue(value, span.provenance, signal);
      this.registerSourceOriginBinding(value, span.provenance);
    }
    if (
      phase.failures.length > 0 ||
      phase.oversized ||
      phase.results.some((result) => result.metadata?.["failureKind"] !== undefined)
    ) {
      const incomplete: EgressInspection = {
        verdict: "block",
        reasons: [REASON_CODES.egress_inspection_incomplete],
        inspectedBytes: payload.byteLength,
        matchCount: 0,
      };
      this.trace.append("egress_inspection", {
        sink: payload.sink,
        verdict: incomplete.verdict,
        inspectedBytes: incomplete.inspectedBytes,
        matchCount: 0,
        reasons: incomplete.reasons,
      });
      return incomplete;
    }
    const result = this.sourceSinkCheck.inspect(payload, signal);
    if (result.verdict === "block" || result.matchCount > 0) {
      this.trace.append("egress_inspection", {
        sink: payload.sink,
        verdict: result.verdict,
        inspectedBytes: result.inspectedBytes,
        matchCount: result.matchCount,
        ...(result.matchedSources !== undefined
          ? {
              sources: result.matchedSources.map((source) => ({
                fingerprint: source.fingerprint,
                provenance: source.provenance,
              })),
            }
          : {}),
        ...(result.reasons.length > 0 ? { reasons: result.reasons } : {}),
      });
    }
    return result;
  }

  private async actionEgressEvaluation(
    action: CanonicalAction,
    intent?: ActionIntent,
  ): Promise<ActionEgressEvaluation> {
    const reasons = new Set<ReasonCode>();
    let matchCount = 0;
    for (const payload of actionEgressPayloads(action, intent)) {
      const result = await this.inspectEgress(payload);
      matchCount += result.matchCount;
      if (result.verdict === "block") for (const reason of result.reasons) reasons.add(reason);
    }
    return { reasons: [...reasons], matchCount };
  }

  private crossOriginExfiltrationReasons(
    action: CanonicalAction,
    egress: ActionEgressEvaluation,
  ): readonly ReasonCode[] {
    const handles = detectHandles(action);
    const declaredHandles = handles.every((handle) =>
      (this.contract.secrets ?? []).some(
        (binding) => binding.name === handle.name && binding.kind === handle.kind,
      ),
    );
    if (handles.length > 0 && !declaredHandles) return [];
    const destination = action.destination ?? action.target?.origin;
    const destinationOrigin = destination === undefined ? null : originOf(destination);
    const matchedValueBlocked = egress.reasons.includes(REASON_CODES.sensitive_value_in_egress);
    // Handles are inert on every PS-019 action surface. The only v0.1
    // executor-supported secret sinks are exact FILL/TYPE/select operations,
    // which are intentionally outside this rule's action set.
    const exactSinkBound = egress.matchCount > 0 && !matchedValueBlocked && handles.length === 0;
    const envelopeReasons = this.envelope.evaluate({
      type: action.type,
      ...(action.destination !== undefined ? { destination: action.destination } : {}),
      ...(action.target !== undefined ? { target: action.target } : {}),
    }).reasons;
    const destinationInTaskScope =
      destinationOrigin !== null &&
      !this.envelope.blockedOrigins.includes(destinationOrigin) &&
      (destinationOrigin === this.currentOrigin ||
        destinationOrigin === action.target?.origin ||
        this.envelope.allowedOrigins.includes(destinationOrigin)) &&
      !envelopeReasons.includes(REASON_CODES.destination_not_allowed);
    return evaluateCrossOriginExfiltration(action, {
      ...(this.currentOrigin !== undefined ? { currentOrigin: this.currentOrigin } : {}),
      sessionTainted:
        this.taintFloor !== undefined && action.instructionProvenance.trust !== "user",
      valueMatched: egress.matchCount > 0,
      handlePresent: handles.length > 0,
      exactSinkBound,
      destinationInTaskScope,
    }).reasons;
  }

  private registerSourceValue(
    value: string,
    provenance: DataProvenance,
    signal?: AbortSignal,
  ): boolean {
    return this.sourceSinkCheck.register({ value, provenance }, signal) !== "incomplete";
  }

  private registerSourceOriginBinding(value: string, provenance: DataProvenance): void {
    if (provenance.origin === undefined) return;
    this.addSensitiveBinding(hash(value), {
      origins: new Set([provenance.origin]),
      fieldTypes: new Set(EGRESS_SINKS),
    });
  }

  private registerSensitiveBindings(value: string, handle: SecretHandle): void {
    const fingerprint = hash(value);
    for (const binding of this.contract.secrets ?? []) {
      if (binding.name === handle.name && binding.kind === handle.kind) {
        this.addSensitiveBinding(fingerprint, {
          origins: new Set(binding.origins),
          fieldTypes: new Set(binding.fieldTypes),
        });
      }
    }
  }

  private addSensitiveBinding(fingerprint: string, binding: SensitiveEgressBinding): void {
    let bindings = this.sensitiveEgressBindings.get(fingerprint);
    if (bindings === undefined) {
      bindings = [];
      this.sensitiveEgressBindings.set(fingerprint, bindings);
    }
    if (
      bindings.some(
        (existing) =>
          setEquals(existing.origins, binding.origins) &&
          setEquals(existing.fieldTypes, binding.fieldTypes),
      )
    ) {
      return;
    }
    bindings.push(binding);
  }

  private evaluateRouteRequest(mutation: NetworkMutation, egressInspection?: EgressInspection) {
    // A routed redirect has an active abort hook. Count each observed redirect
    // transition before continuing it; a rejected reservation is a terminal
    // deterministic block (INV-09/16), not merely trace evidence.
    if (
      mutation.surface === "redirect" &&
      mutation.enforcement === "enforced" &&
      !this.reserveBudget([{ kind: "redirectHops" }])
    ) {
      return {
        verdict: "block",
        reasons: [REASON_CODES.budget_exceeded],
        enforcement: mutation.enforcement,
        provenance: mutation.provenance,
      } as const;
    }
    const correlation = correlateNetworkMutation(
      mutation,
      mutation.actionIntentId === undefined ? undefined : this.activePostAction?.intent,
      this.clock.now(),
    );
    const decision = evaluateNetworkMutation({
      mutation,
      envelope: this.envelope,
      riskState: this.risk,
      destinationRules: this.policy.destinationRules ?? DEFAULT_DESTINATION_RULES,
      ...(egressInspection !== undefined ? { egressInspection } : {}),
      correlation,
    });
    this.evaluatedNetworkMutations.add(mutation);
    this.trace.append("network_mutation", {
      surface: mutation.surface,
      initiator: mutation.initiator,
      destination: mutation.destination,
      enforcement: mutation.enforcement,
      provenance: mutation.provenance,
      verdict: decision.verdict,
      reasons: decision.reasons,
      correlation: correlation.status,
      ...(correlation.intentId !== undefined ? { intentId: correlation.intentId } : {}),
    });
    this.applyNetworkRisk(decision.reasons);
    return decision;
  }

  private applyNetworkRisk(reasons: readonly ReasonCode[]): void {
    if (reasons.includes(REASON_CODES.sensitive_value_in_egress)) {
      this.applyRiskSignal("secret_requested");
    } else if (
      reasons.some(
        (reason) =>
          reason === REASON_CODES.private_network_destination ||
          reason === REASON_CODES.destination_not_allowed ||
          reason === REASON_CODES.network_origin_not_allowed,
      )
    ) {
      this.applyRiskSignal("cross_origin_redirect");
    }
  }

  private evaluateRiskAction(action: CanonicalAction): "allow" | "require_approval" | "block" {
    if (this.risk === "NORMAL") return "allow";
    if (this.risk === "QUARANTINED") return "block";

    const sourceOrigin = this.currentOrigin ?? action.target?.origin;
    const sameSiteNavigation =
      action.type === "NAVIGATE" &&
      action.destination !== undefined &&
      sourceOrigin !== undefined &&
      sameSite(action.destination, sourceOrigin);

    if (this.risk === "READ_ONLY") {
      if (action.type === "READ" || action.type === "SCROLL") return "allow";
      return sameSiteNavigation && action.navigationOrigin === "link" ? "allow" : "block";
    }

    // RESTRICTED preserves only the narrowly defined progress actions. A
    // missing trusted origin is never treated as same-origin/same-site.
    if (action.type === "READ" || action.type === "SCROLL") return "allow";
    if (sameSiteNavigation) return "allow";
    // Cross-origin navigation is expressly excluded from the RESTRICTED
    // action set. This is a state-bound block, not an approval candidate, so
    // its stable reason remains visible alongside a policy-layer block.
    if (action.type === "NAVIGATE") return "block";
    if (detectHandles(action.data).length > 0) {
      return this.hasPreviouslyApprovedSecretHandle(action) ? "allow" : "block";
    }
    if (
      (action.type === "CLICK" || action.type === "TYPE" || action.type === "FILL") &&
      sourceOrigin !== undefined &&
      action.target?.origin !== undefined &&
      sameOrigin(sourceOrigin, action.target.origin) &&
      detectHandles(action.data).length === 0
    ) {
      return "allow";
    }
    if (action.type === "DOWNLOAD" && this.envelope.downloads) return "allow";
    return isHighImpact(action) ? "require_approval" : "block";
  }

  /** Reject handles absent from the trusted contract before any scanner sees them. */
  private unboundHandleReasons(action: CanonicalAction): readonly ReasonCode[] {
    const declared = this.contract.secrets ?? [];
    // `raw` is adapter-owned operation data and may carry headers, paths,
    // bodies, or messages not represented by the canonical convenience
    // fields. It remains part of the proposed operation for this mandatory
    // handle check; opaque handles themselves are safe for scanners/traces.
    const handles = detectHandles(action);
    return handles.some(
      (handle) =>
        !declared.some((binding) => binding.name === handle.name && binding.kind === handle.kind),
    )
      ? [REASON_CODES.secret_sink_not_allowed]
      : [];
  }

  private hasPreviouslyApprovedSecretHandle(action: CanonicalAction): boolean {
    const handles = detectHandles(action);
    return (
      handles.length > 0 &&
      handles.every((handle) => {
        const prefix = `${serializeHandle(handle)}|`;
        return [...this.approvedSecretSinks].some((key) => key.startsWith(prefix));
      })
    );
  }

  private createSecretResolver(
    authorized: Authorized,
    issuedState: string,
  ): ScopedSecretResolver | undefined {
    if (this.vault === undefined) return undefined;
    return createScopedSecretResolver({
      authorized,
      bindings: this.contract.secrets ?? [],
      envelope: this.envelope,
      lookup: this.vault.createExecutorLookup(this.vaultAccess ?? createVaultExecutorAccess()),
      restrictedMode: this.policy.secretResolution?.restrictedMode ?? "keep_approved_sinks",
      currentState: () => ({
        riskState: this.risk,
        policyHash: this.policy.policyHash,
        sessionActive: !this.ended,
        actionStateValid: this.approvalStateMatches(authorized.action, issuedState),
      }),
      wasApproved: (sinkKey) => this.approvedSecretSinks.has(sinkKey),
      approve: (sinkKey) => this.approvedSecretSinks.add(sinkKey),
      audit: (attempt) => this.trace.append("secret_resolution", { ...attempt }),
    });
  }

  /**
   * Coarse v0.1 containment for a model plan after hostile context release.
   * This is independent of scanners and semantic evidence; PS-019 extends the
   * same source-to-sink principle to data-bearing egress actions.
   */
  private untrustedNavigationReasons(action: CanonicalAction): readonly ReasonCode[] {
    return action.type === "NAVIGATE" &&
      action.instructionProvenance.trust === "web" &&
      isCrossOrigin(action)
      ? [REASON_CODES.navigation_instruction_originated_from_untrusted_dom]
      : [];
  }

  private hasSessionApprovalGrant(
    action: CanonicalAction,
    policyDecision: { readonly policyHash: string; readonly verdict: AggregateVerdict },
    decidedLayer: string | undefined,
  ): boolean {
    const grant = this.approvalGrants.get(approvalGrantKey(action));
    return (
      grant !== undefined &&
      grant.policyHash === policyDecision.policyHash &&
      grant.riskState === this.risk &&
      policyDecision.verdict === "REQUIRE_APPROVAL" &&
      decidedLayer === "policy"
    );
  }

  private approvalState(action: CanonicalAction): string {
    const budget = this.budgets.snapshot();
    return stableSerialize({
      action,
      policyHash: this.policy.policyHash,
      risk: this.sessionRisk,
      // Elapsed milliseconds naturally advance while a human reads a prompt;
      // bind durable consumption and expiration instead of timing jitter.
      budget: {
        actions: budget.actions,
        navigations: budget.navigations,
        redirectHops: budget.redirectHops,
        guardCalls: budget.guardCalls,
        guardTokens: budget.guardTokens,
        downloads: budget.downloads,
        downloadBytes: budget.downloadBytes,
        uploadBytes: budget.uploadBytes,
        tabs: budget.tabs,
        expired: this.budgets.isExpired(),
      },
      ended: this.ended,
      taintFloor: this.taintFloor ?? null,
    });
  }

  private approvalStateMatches(action: CanonicalAction, expected: string): boolean {
    return this.approvalState(action) === expected;
  }

  private prepareAction(
    action: CanonicalAction,
    options: TrustedInstructionOptions = {},
  ): CanonicalAction {
    const provenance = validateDataProvenance(action.instructionProvenance);
    if (provenance === null) {
      throw new TypeError("action requires valid bounded instruction provenance");
    }
    if (provenance.trust === "user" && options.instructedBy !== "user") {
      throw new TypeError(
        "user instruction provenance requires authorizeActions(..., { instructedBy: user })",
      );
    }
    if (options.instructedBy === "user") {
      return { ...action, instructionProvenance: { trust: "user", timestamp: nowIso(this.clock) } };
    }
    if (this.taintFloor === undefined) {
      return { ...action, instructionProvenance: provenance };
    }
    return {
      ...action,
      // An agent may have transformed the instruction, so retain the source
      // that released hostile context and never let its declared provenance
      // raise trust above the session floor.
      instructionProvenance: {
        ...this.taintFloor,
        trust: leastTrust(provenance.trust, this.taintFloor.trust),
      },
    };
  }

  private releaseUntrustedContext(
    provenance: DataProvenance,
    source: "observation" | "tool_output" | "memory_read",
  ): void {
    const validated = validateDataProvenance(provenance);
    if (validated === null)
      throw new TypeError("released content requires valid bounded provenance");
    const floor: DataProvenance = { ...validated, trust: "web" };
    if (this.taintFloor !== undefined) return;
    this.taintFloor = Object.freeze(floor);
    this.trace.append("taint_activation", { source, provenance: this.taintFloor });
  }
}

function nowIso(clock: SessionClock): string {
  return new Date(clock.now()).toISOString();
}

function isSensitiveMarker(value: string): boolean {
  return /^\[\[OAF_SENSITIVE:(?:SECRET|PII|CREDENTIAL):[a-z0-9_.-]{1,64}\]\]$/.test(value);
}

function setEquals<T>(left: ReadonlySet<T>, right: ReadonlySet<T>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function isAbortSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}

function memoryMarkers(findings: readonly Finding[]): readonly MemoryMarker[] {
  const markers = new Set<MemoryMarker>();
  if (findings.some((finding) => finding.category === "memory_instruction")) {
    markers.add("instruction_removed");
  }
  if (findings.some((finding) => finding.category === "secret_detected")) {
    markers.add("sensitive_value_replaced");
  }
  return [...markers];
}

function helperTraceMetadata(
  action: CanonicalAction,
): { readonly helper: { readonly name: string; readonly sha256: string } } | undefined {
  if (action.type !== "EXECUTE_SCRIPT" || action.data === undefined) return undefined;
  const value = action.data.value;
  if (typeof value !== "object" || value === null) return undefined;
  const helper = (value as Record<string, unknown>)["helper"];
  if (typeof helper !== "object" || helper === null) return undefined;
  const name = (helper as Record<string, unknown>)["name"];
  const sha256 = (helper as Record<string, unknown>)["sha256"];
  if (
    typeof name !== "string" ||
    typeof sha256 !== "string" ||
    !/^[a-z][a-z0-9_.-]{0,63}$/.test(name) ||
    !/^[a-f0-9]{64}$/i.test(sha256)
  ) {
    return undefined;
  }
  return { helper: { name, sha256 } };
}

function provenanceOf(payload: PhasePayload): DataProvenance {
  switch (payload.kind) {
    case "observation":
      return payload.observation.provenance;
    case "proposedAction":
      return payload.action.instructionProvenance;
    case "modelOutput":
      return payload.output.provenance;
    case "memoryCandidate":
      return payload.candidate.provenance;
    case "egressPayload":
      return payload.payload.provenance;
    default:
      return { trust: "tool", timestamp: new Date().toISOString() };
  }
}

function sanitizeApprovalAction(
  action: CanonicalAction,
  redactor: RedactionRegistry,
): CanonicalAction {
  const data =
    action.data !== undefined &&
    (action.instructionProvenance.trust === "application" ||
      action.instructionProvenance.trust === "user") &&
    (action.data.provenance.trust === "application" || action.data.provenance.trust === "user")
      ? {
          value: redactDeep(action.data.value, redactor),
          provenance: { trust: action.data.provenance.trust },
        }
      : undefined;
  return {
    type: action.type,
    ...(action.destination !== undefined
      ? { destination: approvalOrigin(action.destination) }
      : {}),
    ...(action.target?.origin !== undefined
      ? { target: { origin: approvalOrigin(action.target.origin) } }
      : {}),
    ...(data !== undefined ? { data } : {}),
    instructionProvenance: { trust: action.instructionProvenance.trust },
  };
}

function withoutRawOperation(action: CanonicalAction): CanonicalAction {
  return {
    type: action.type,
    ...(action.navigationOrigin !== undefined ? { navigationOrigin: action.navigationOrigin } : {}),
    ...(action.target !== undefined ? { target: action.target } : {}),
    ...(action.destination !== undefined ? { destination: action.destination } : {}),
    ...(action.data !== undefined
      ? { data: provenanced("[REDACTED]", action.data.provenance) }
      : {}),
    instructionProvenance: action.instructionProvenance,
    ...(action.sideEffectClass !== undefined ? { sideEffectClass: action.sideEffectClass } : {}),
  };
}

function provenanceAfterSanitization(
  observation: DataProvenance,
  phase: {
    readonly sanitizedTexts: readonly ProvenancedDatum<string>[];
    readonly sanitizationSpans: readonly { readonly provenance: DataProvenance }[];
  },
): DataProvenance {
  let result = observation;
  for (const sanitized of phase.sanitizedTexts) {
    if (leastTrust(result.trust, sanitized.provenance.trust) === sanitized.provenance.trust) {
      result = sanitized.provenance;
    }
  }
  for (const span of phase.sanitizationSpans) {
    if (leastTrust(result.trust, span.provenance.trust) === span.provenance.trust) {
      result = span.provenance;
    }
  }
  return result;
}

function sanitizeApprovalFindings(
  findings: readonly Finding[],
  redactor: RedactionRegistry,
): readonly Finding[] {
  return findings.map((finding) => ({
    // Findings may quote page, tool, or provider text. The handler gets only
    // firewall-owned classification fields plus a one-way evidence reference;
    // none of that content can masquerade as an approval instruction.
    id: finding.id,
    category: finding.category,
    title: "Firewall finding",
    description: "A firewall finding requires review.",
    source: { type: finding.source.type },
    provenance: { trust: finding.provenance.trust },
    evidence: redactor.redact(hash(finding.evidence)),
    recommendedAction: finding.recommendedAction,
    ...(finding.severity !== undefined ? { severity: finding.severity } : {}),
    ...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
  }));
}

function approvalOrigin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return "invalid-origin";
  }
}

/** Session approval is scoped to the action class and destination/sink origin. */
function approvalGrantKey(action: CanonicalAction): string {
  const origin =
    action.destination !== undefined
      ? approvalOrigin(action.destination)
      : action.target?.origin !== undefined
        ? approvalOrigin(action.target.origin)
        : "no-origin";
  return `${action.type}:${origin}`;
}

function budgetUsesFor(action: CanonicalAction): readonly BudgetUse[] {
  const uses: BudgetUse[] = [{ kind: "actions" }];
  if (action.type === "NAVIGATE") uses.push({ kind: "navigations" });
  if (action.type === "DOWNLOAD") uses.push({ kind: "downloads" });
  if (action.type === "UPLOAD")
    uses.push({ kind: "uploadBytes", amount: uploadByteLength(action.data) });
  return uses;
}

function uploadByteLength(data: unknown): number {
  if (!isRecord(data) || !isRecord(data["value"]) || !Array.isArray(data["value"]["files"])) {
    return Number.POSITIVE_INFINITY;
  }
  let total = 0;
  for (const file of data["value"]["files"]) {
    if (
      !isRecord(file) ||
      typeof file["bytes"] !== "number" ||
      !Number.isSafeInteger(file["bytes"]) ||
      file["bytes"] < 0
    ) {
      return Number.POSITIVE_INFINITY;
    }
    total += file["bytes"];
    if (!Number.isSafeInteger(total)) return Number.POSITIVE_INFINITY;
  }
  return total;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function appendReason(reasons: readonly ReasonCode[], reason: ReasonCode): readonly ReasonCode[] {
  return reasons.includes(reason) ? reasons : [...reasons, reason];
}

function uniqueReasons(reasons: readonly ReasonCode[]): readonly ReasonCode[] {
  return [...new Set(reasons)];
}

function observationText(observation: PageObservation): string {
  if (observation.ariaSnapshot !== undefined) {
    return observation.ariaSnapshot;
  }
  const nodes = observation.probe?.nodes ?? [];
  return nodes.map((n) => n.text).join("\n");
}

function redactPublicObservation(
  observation: PageObservation,
  redactor: RedactionRegistry,
): PageObservation {
  const { screenshot, ...textual } = observation;
  const redacted = redactDeep(textual, redactor) as Omit<PageObservation, "screenshot">;
  return {
    ...redacted,
    ...(screenshot !== undefined ? { screenshot } : {}),
  };
}

function isSafeRevalidationError(error: unknown, redactor: RedactionRegistry): boolean {
  if (typeof error !== "object" || error === null) return false;
  const record = error as {
    readonly name?: unknown;
    readonly reason?: unknown;
    readonly message?: unknown;
  };
  return (
    record.name === "PlaywrightRevalidationError" &&
    typeof record.reason === "string" &&
    isReasonCode(record.reason) &&
    record.message === record.reason &&
    !redactor.containsSecret(record.reason)
  );
}

/** Redact every plugin-controlled presentation field before it becomes public. */
function redactFinding(finding: Finding, redactor: RedactionRegistry): Finding {
  return {
    ...finding,
    title: redactor.redact(finding.title),
    description: redactor.redact(finding.description),
    source: {
      ...finding.source,
      ...(finding.source.selector !== undefined
        ? { selector: redactor.redact(finding.source.selector) }
        : {}),
      ...(finding.source.xpath !== undefined
        ? { xpath: redactor.redact(finding.source.xpath) }
        : {}),
      ...(finding.source.origin !== undefined
        ? { origin: redactor.redact(finding.source.origin) }
        : {}),
      ...(finding.source.frameOrigin !== undefined
        ? { frameOrigin: redactor.redact(finding.source.frameOrigin) }
        : {}),
    },
    evidence: redactor.redact(finding.evidence),
  };
}

/** Build reproducible, redacted evidence references from findings (INV-17). */
function evidenceReferences(findings: readonly Finding[]): EvidenceReference[] {
  return findings.map((finding) => ({
    findingId: finding.id,
    category: finding.category,
    evidenceHash: hash(finding.evidence),
    sourceType: finding.source.type,
  }));
}

export type { ReasonCode };
