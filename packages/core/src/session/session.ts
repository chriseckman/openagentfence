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
import { denyAllResolver } from "../secrets/resolver.js";
import { wrapUntrustedContent, type UntrustedContent } from "../contracts/untrusted-content.js";
import type { Finding } from "../contracts/finding.js";
import type { AggregateVerdict } from "../contracts/verdict.js";
import type { BrowserAdapter } from "../adapter/browser-adapter.js";
import type { AdapterEvent, AdapterEventSink } from "../adapter/browser-adapter.js";
import type { NetworkMutation } from "../network/mutation.js";
import { DEFAULT_DESTINATION_RULES, evaluateDestination } from "../network/destination.js";
import type { VaultAdapter } from "../secrets/vault-adapter.js";
import type { PolicyEngine } from "../policy/engine.js";
import {
  SessionBudgetLedger,
  systemSessionClock,
  type BudgetUse,
  type SessionClock,
} from "./budgets.js";
import type { GuardModelProvider } from "../guard/provider.js";
import type { TraceWriter } from "../trace/writer.js";
import { redactDeep } from "../trace/writer.js";
import type { TraceDocument, EvidenceReference } from "../trace/events.js";
import { hash, type RedactionRegistry } from "../trace/redact.js";
import type { PageObservation } from "../adapter/observation.js";
import type { SecurityPhase } from "../contracts/phase.js";
import type { SecurityContext, PhasePayload } from "../scanner/context.js";
import { ScannerRegistry } from "../orchestrator/registry.js";
import { runPhase } from "../orchestrator/run-phase.js";
import { type ResourceLimits } from "../orchestrator/limits.js";
import { applySanitizations, applySanitizationSpans } from "../orchestrator/sanitize.js";
import { riskAggregator } from "../risk/aggregator.js";
import { applyRiskSignal, type RiskSignal } from "../risk/engine.js";
import type { RiskAssessment } from "../contracts/risk-assessment.js";
import { isHighImpact } from "../action/classify.js";
import { sameOrigin, sameSite } from "../action/url.js";
import { detectHandles } from "../secrets/handle-codec.js";
import { REASON_CODES, type ReasonCode } from "../policy/reasons.js";
import type { ApprovalDecision, ApprovalHandler, ApprovalRequest } from "./approval.js";
import { resolveApproval } from "./approval.js";
import type { SessionDecision, SessionEvents } from "./events.js";

const DEFAULT_APPROVAL_TIMEOUT_MS = 30_000;

interface ActivePostAction {
  readonly action: CanonicalAction;
  readonly intent: ActionIntent;
  readonly startedOrigin: string | undefined;
  readonly events: AdapterEvent[];
  status: PostActionStatus;
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
  readonly vault?: VaultAdapter;
  readonly approvalHandler?: ApprovalHandler;
  readonly trace: TraceWriter;
  readonly clock?: SessionClock;
}

export interface PerceptionResult {
  readonly observation: PageObservation;
  readonly sanitizedText: string;
  readonly findings: readonly Finding[];
  readonly assessment: RiskAssessment;
}

/** Result of binding a successful session decision to adapter-inspected state. */
export interface BoundAuthorizationResult {
  readonly decision: SessionDecision;
  readonly authorized?: Authorized;
}

/**
 * Narrow bridge for adapters which have an exact structured executor but do
 * not implement the browser event contract. The callback receives no raw
 * action and is invoked only after core has atomically consumed a
 * session-issued authorization.
 */
export interface ExactActionExecutor {
  execute(): Promise<unknown>;
}

/**
 * One browser context = one session (ARCHITECTURE §5). Owns the envelope, risk
 * state, trace, event stream, approval plumbing, and the escape hatch, and
 * runs the minimal perceive/authorize pipeline used by the M2 vertical slice.
 */
export class SecuritySession {
  readonly id: string;
  readonly envelope: CapabilityEnvelope;

  private readonly adapter: BrowserAdapter;
  private readonly contract: TaskContract;
  private readonly policy: PolicyEngine;
  private readonly registry: ScannerRegistry;
  private readonly redactor: RedactionRegistry;
  private readonly limits: ResourceLimits;
  private readonly guardModel: GuardModelProvider | undefined;
  private readonly vault: VaultAdapter | undefined;
  private readonly approvalHandler: ApprovalHandler | undefined;
  private readonly trace: TraceWriter;
  private readonly budgets: SessionBudgetLedger;
  private readonly clock: SessionClock;

  private risk: RiskState = "NORMAL";
  private score = 0;
  private currentOrigin: string | undefined;
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
  private activePostAction: ActivePostAction | undefined;
  private readonly unsubscribeEvents: () => void;

  private readonly listeners = new Map<keyof SessionEvents, Set<(event: unknown) => void>>();

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
    this.approvalHandler = init.approvalHandler;
    this.trace = init.trace;
    this.clock = init.clock ?? systemSessionClock;
    this.budgets = new SessionBudgetLedger(init.contract.budgets, this.clock.now(), this.clock);
    const sink: AdapterEventSink = {
      onNavigation: (event) => this.recordAdapterEvent(event),
      onPopup: (event) => this.recordAdapterEvent(event),
      onDownload: (event) => this.recordAdapterEvent(event),
      onNetworkMutation: (mutation) => this.recordNetworkMutation(mutation),
      onRouteRequest: (mutation) => this.evaluateRouteRequest(mutation),
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

  get sessionRisk(): SessionRisk {
    return { state: this.risk, score: this.score };
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
    const observation = await this.adapter.observe();
    this.currentOrigin = observation.origin;
    const ctx = this.buildContext("PERCEPTION", { kind: "observation", observation });
    const phase = await runPhase(this.registry, "PERCEPTION", ctx, this.limits);

    const findings = phase.results.flatMap((r) => r.findings);
    const baseText = observationText(observation);
    const spanSanitized = applySanitizationSpans(baseText, phase.sanitizationSpans);
    const sanitizedText = applySanitizations(spanSanitized, phase.sanitizedTexts);

    const assessment = riskAggregator.aggregate({
      scanResults: phase.results,
      policyDecision: { verdict: "ALLOW", reasons: [], matchedRules: [], policyHash: "perception" },
      riskState: this.risk,
      score: this.score,
      budgetsExhausted: false,
    });

    this.trace.append("observation", { url: observation.url, origin: observation.origin });
    for (const failure of phase.failures) {
      this.trace.append("scan_result", { scanner: failure.scanner, failureKind: failure.kind });
    }
    for (const finding of findings) {
      this.trace.append("finding", {
        id: finding.id,
        category: finding.category,
        sourceType: finding.source.type,
        evidenceHash: hash(finding.evidence),
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
    }

    return {
      observation,
      sanitizedText,
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
    this.trace.append("proposed_action", { type: action.type });
    this.trace.append("canonical_action", {
      type: action.type,
      ...helperTraceMetadata(action),
    });

    const builtInReasons = this.unboundHandleReasons(action);
    if (builtInReasons.length > 0) {
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
    if (intent.policyHash !== this.policy.policyHash || isIntentExpired(intent)) {
      const reason =
        intent.policyHash !== this.policy.policyHash
          ? REASON_CODES.action_policy_mismatch
          : REASON_CODES.action_intent_expired;
      const decision = this.recordDecision(action, "BLOCK", [reason], this.policy.policyHash);
      this.trace.append("action_revalidation", { reason, intentId: intent.intentId });
      return { decision };
    }
    const decision = await this.authorize(action);
    if (decision.verdict !== "ALLOW") {
      return { decision };
    }
    const decisionId = randomBytes(8).toString("hex");
    const authorized = mintAuthorizedAction({
      action,
      intent,
      operationHash: intent.operationHash,
      policyHash: this.policy.policyHash,
      decisionId,
      traceId: decisionId,
    });
    this.trace.append("authorized_action", { intentId: intent.intentId, decisionId });
    // Bind the authorization to every firewall-owned input that can change
    // between decision and side effect: policy, risk, budget, grants, action
    // identity, and session liveness. This snapshot deliberately excludes
    // wall-clock churn; expiry is checked independently below.
    this.issuedAuthorizations.set(authorized, this.approvalState(action));
    return { decision, authorized };
  }

  /** Execute only a core-minted authorization through the adapter boundary. */
  async executeAuthorized(authorized: Authorized): Promise<unknown> {
    return this.executeIssuedAuthorization(authorized, () =>
      this.adapter.executeAuthorized(authorized, denyAllResolver),
    );
  }

  /**
   * Consume a state-bound authorization through a framework-owned exact
   * executor which lacks BrowserAdapter event hooks (currently Stagehand).
   * Such executions are recorded as post-action observation unavailable and
   * therefore cannot establish a clean post-action state.
   */
  async executeAuthorizedWith(
    authorized: Authorized,
    executor: ExactActionExecutor,
  ): Promise<unknown> {
    return this.executeIssuedAuthorization(authorized, () => executor.execute(), "unavailable");
  }

  private async executeIssuedAuthorization(
    authorized: Authorized,
    execute: () => Promise<unknown>,
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
      const result = await execute();
      this.trace.append("execution", {
        intentId: authorized.intent.intentId,
        type: authorized.action.type,
      });
      return result;
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
  async inspectUntrustedText(content: string, maxBytes = 65_536): Promise<UntrustedContent> {
    if (Buffer.byteLength(content, "utf8") > maxBytes) {
      throw new RangeError("untrusted adapter output exceeds the configured byte limit");
    }
    const ctx = this.buildContext("MODEL_OUTPUT", {
      kind: "modelOutput",
      output: { content, provenance: { trust: "web" } },
    });
    const phase = await runPhase(this.registry, "MODEL_OUTPUT", ctx, this.limits);
    if (phase.failures.length > 0) {
      throw new Error(REASON_CODES.scanner_unavailable);
    }
    const sanitized = applySanitizations(content, phase.sanitizedTexts);
    return wrapUntrustedContent({ content: sanitized, provenance: { trust: "web" } });
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
    return {
      rawPage(reason: string): unknown {
        if (typeof reason !== "string" || reason.trim().length === 0) {
          throw new TypeError("unsafe.rawPage requires a non-empty reason");
        }
        // Recorded before raw-handle access (INV-18), with the caller reason
        // redacted so a secret-bearing reason never reaches the trace.
        trace.append("escape_hatch", { reason: redactor.redact(reason) });
        return adapter.rawPage(reason);
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
    this.unsubscribeEvents();
    this.trace.append("session_end", { risk: this.risk, score: this.score });
    if (this.vault !== undefined) {
      await this.vault.invalidateSession();
    }
    return this.trace.document();
  }

  private buildContext(phase: SecurityPhase, payload: PhasePayload): SecurityContext {
    return {
      phase,
      sessionId: this.id,
      taskContract: this.contract,
      envelope: this.envelope,
      riskState: this.risk,
      payload,
      provenance: { trust: "web" },
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
    this.trace.append("network_mutation", {
      surface: mutation.surface,
      initiator: mutation.initiator,
      destination: mutation.destination,
      enforcement: mutation.enforcement,
    });
  }

  private evaluateRouteRequest(mutation: NetworkMutation) {
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
      } as const;
    }
    const outcome = evaluateDestination({
      destination: mutation.destination,
      ...(mutation.origin !== undefined ? { sourceOrigin: mutation.origin } : {}),
      enforceNavigationScope: mutation.surface === "navigation" || mutation.surface === "redirect",
      ...(mutation.redirectHops !== undefined ? { redirectHops: mutation.redirectHops } : {}),
      envelope: this.envelope,
      rules: this.policy.destinationRules ?? DEFAULT_DESTINATION_RULES,
    });
    if (!outcome.allowed) {
      this.trace.append("network_mutation", {
        surface: mutation.surface,
        initiator: mutation.initiator,
        destination: mutation.destination,
        enforcement: mutation.enforcement,
        verdict: "block",
        reasons: outcome.reasons,
      });
    }
    return {
      verdict: outcome.allowed ? "continue" : "block",
      reasons: outcome.reasons,
      enforcement: mutation.enforcement,
    } as const;
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
    if (detectHandles(action.data).length > 0) return "block";
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
    });
  }

  private approvalStateMatches(action: CanonicalAction, expected: string): boolean {
    return this.approvalState(action) === expected;
  }
}

function helperTraceMetadata(
  action: CanonicalAction,
): { readonly helper: { readonly name: string; readonly sha256: string } } | undefined {
  if (action.type !== "EXECUTE_SCRIPT" || typeof action.data !== "object" || action.data === null)
    return undefined;
  const helper = (action.data as Record<string, unknown>)["helper"];
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

function sanitizeApprovalAction(
  action: CanonicalAction,
  redactor: RedactionRegistry,
): CanonicalAction {
  const data =
    action.instructionProvenance.trust === "application" ||
    action.instructionProvenance.trust === "user"
      ? redactDeep(action.data, redactor)
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
    ...(action.data !== undefined ? { data: action.data } : {}),
    instructionProvenance: action.instructionProvenance,
    ...(action.sideEffectClass !== undefined ? { sideEffectClass: action.sideEffectClass } : {}),
  };
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
  if (!isRecord(data) || !Array.isArray(data["files"])) return Number.POSITIVE_INFINITY;
  let total = 0;
  for (const file of data["files"]) {
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

function observationText(observation: PageObservation): string {
  if (observation.ariaSnapshot !== undefined) {
    return observation.ariaSnapshot;
  }
  const nodes = observation.probe?.nodes ?? [];
  return nodes.map((n) => n.text).join("\n");
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
