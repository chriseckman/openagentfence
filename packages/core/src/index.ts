/**
 * @packageDocumentation
 * Framework-neutral v0.1 contracts and composition API.
 * @experimental
 */

// Contracts
export { SECURITY_PHASES, isSecurityPhase } from "./contracts/phase.js";
export type { SecurityPhase } from "./contracts/phase.js";

export {
  TRUST_LEVELS,
  TRUST_ORDER,
  WEB_PROVENANCE,
  leastTrust,
  provenanced,
  validateDataProvenance,
} from "./contracts/provenance.js";
export type { DataProvenance, ProvenancedDatum, TrustLevel } from "./contracts/provenance.js";

export { createSourceSinkCheck } from "./provenance/source-sink.js";
export type { SourceSinkCheck, SourceSinkCheckOptions } from "./provenance/source-sink.js";
export { SourceValueRegistry, DEFAULT_SOURCE_VALUE_LIMITS } from "./provenance/value-registry.js";
export type {
  SourceValueEvidence,
  SourceValueMatch,
  SourceValueRegistration,
  SourceValueRegistryLimits,
} from "./provenance/value-registry.js";

export { SCANNER_VERDICTS, AGGREGATE_VERDICTS, SCANNER_TO_AGGREGATE } from "./contracts/verdict.js";
export type { ScannerVerdict, AggregateVerdict } from "./contracts/verdict.js";

export { RISK_STATES, RISK_STATE_ORDER, maxRiskState } from "./contracts/risk-state.js";
export type { RiskState, SessionRisk } from "./contracts/risk-state.js";

export { SEVERITIES } from "./contracts/finding.js";
export type {
  Severity,
  BoundingBox,
  FindingSourceType,
  FindingSource,
  Finding,
} from "./contracts/finding.js";

export type { ScanResult } from "./contracts/scan-result.js";
export type { RiskAssessment } from "./contracts/risk-assessment.js";

export { validateTaskContract, isValidatedTaskContract } from "./contracts/task-contract.js";
export type {
  TaskContract,
  TaskCapabilities,
  NavigationMode,
  SecretBindingDecl,
  OriginAllowances,
  BudgetConfig,
  ApprovalConfig,
  ValidationResult,
  ValidatedTaskContract,
} from "./contracts/task-contract.js";

export { validateFinding, validateScanResult } from "./contracts/validation.js";

export {
  validateTrustedIntentContext,
  buildTrustedIntentContext,
  isTrustedIntent,
} from "./contracts/trusted-intent-context.js";
export type {
  TrustedIntentContext,
  TrustedIntent,
  TrustedIntentValidationResult,
} from "./contracts/trusted-intent-context.js";
export { validateUntrustedContent, wrapUntrustedContent } from "./contracts/untrusted-content.js";
export type { UntrustedContent, UntrustedContentInput } from "./contracts/untrusted-content.js";

export {
  MEMORY_ITEM_SCHEMA_VERSION,
  MAX_MEMORY_CONTENT_BYTES,
  MAX_MEMORY_MARKERS,
  MEMORY_SENSITIVITIES,
  MEMORY_MARKERS,
  createStoredMemoryItem,
  memoryItemHash,
  memoryReadDatum,
  validateMemoryWriteCandidate,
  validateStoredMemoryItem,
} from "./memory/item.js";
export type {
  MemorySensitivity,
  MemoryMarker,
  MemoryWriteCandidate,
  StoredMemoryItem,
} from "./memory/item.js";
export { MEMORY_GUARD_REASONS, MemoryGuardError } from "./memory/guard.js";
export type { MemoryGuardReason, MemoryWriteResult, SessionMemoryGuard } from "./memory/guard.js";

// Action
export { ACTION_TYPES, SIDE_EFFECT_CLASSES } from "./action/canonical-action.js";
export type {
  ActionType,
  SideEffectClass,
  ActionTarget,
  CanonicalAction,
} from "./action/canonical-action.js";
export { isHighImpact, isCrossOrigin } from "./action/classify.js";
export { unknownActionNormalizer } from "./action/normalizer.js";
export type { ActionNormalizer } from "./action/normalizer.js";
export { originOf, hostnameOf, sameOrigin, sameSite } from "./action/url.js";
export { stableSerialize, fingerprint } from "./action/state-fingerprint.js";
export {
  validateActionIntent,
  computeIntentFingerprint,
  intentBoundState,
  isIntentExpired,
  compareIntentState,
} from "./action/intent.js";
export type {
  ActionIntent,
  ObservationIdentity,
  TargetIdentity,
  IntentMismatchCode,
  IntentStateSnapshot,
} from "./action/intent.js";
export {
  POST_ACTION_SETTLE_MS,
  POST_ACTION_MAX_EVENTS,
  comparePostAction,
  postActionCapabilitiesAvailable,
} from "./action/post-action.js";
export type {
  PostActionObservation,
  PostActionReason,
  PostActionStatus,
} from "./action/post-action.js";
// Minting is deliberately internal to SecuritySession. Exporting the
// constructor would let an application fabricate a branded value and bypass
// PRE_ACTION authorization; adapters receive the opaque brand only from core.
export { isAuthorizedAction } from "./action/authorized.js";
export type { AuthorizedAction, Authorized } from "./action/authorized.js";

// Secrets
export {
  HANDLE_KINDS,
  parseHandle,
  serializeHandle,
  detectHandles,
} from "./secrets/handle-codec.js";
export type { SecretHandleKind, SecretHandle } from "./secrets/handle-codec.js";
export type { SinkBinding, SinkTarget } from "./secrets/sink-binding.js";
export { inferSecretFieldType } from "./secrets/field-type.js";
export type { VaultAdapter, SessionVault, ExecutorSecretLookup } from "./secrets/vault-adapter.js";
export { isVaultExecutorAccess } from "./secrets/vault-access.js";
export type { VaultExecutorAccess } from "./secrets/vault-access.js";
export { denyAllResolver } from "./secrets/resolver.js";
export type {
  SecretResolver,
  ResolverSessionState,
  SecretResolutionAudit,
} from "./secrets/resolver.js";

// Egress
export { EGRESS_SINKS } from "./egress/payload.js";
export type { EgressPayload, EgressSink } from "./egress/payload.js";
export { MAX_EGRESS_VALUE_BYTES, egressMatchForms } from "./egress/match.js";
export { createEgressInspector } from "./egress/inspect.js";
export { actionEgressPayloads } from "./egress/action.js";
export {
  EXFILTRATION_ACTION_TYPES,
  evaluateCrossOriginExfiltration,
} from "./egress/exfiltration.js";
export type {
  CrossOriginExfiltrationEvaluation,
  CrossOriginExfiltrationFacts,
} from "./egress/exfiltration.js";
export type {
  EgressInspector,
  EgressInspectorOptions,
  EgressInspection,
  EgressMatchResult,
} from "./egress/inspect.js";

// Envelope
export {
  compileTaskContract,
  secureDefaultEnvelope,
  envelopeAllowsAtLeast,
} from "./envelope/compile.js";
export { SECURE_DEFAULT_CAPABILITIES } from "./envelope/defaults.js";
export type {
  CapabilityEnvelope,
  ResolvedCapabilities,
  ActionShape,
  EnvelopeEvaluation,
  EnvelopeNarrowing,
} from "./envelope/envelope.js";

// Policy
export { REASON_CODES, REASON_CODE_DESCRIPTIONS, isReasonCode } from "./policy/reasons.js";
export type { ReasonCode } from "./policy/reasons.js";
export type { PolicyDecision } from "./policy/decision.js";
export type { PolicyEngine, PolicyEvaluationInput } from "./policy/engine.js";
export {
  createPolicyRuntimeState,
  emptyPolicyRuntimeState,
  isValidatedPolicyRuntimeState,
} from "./policy/runtime-state.js";
export type {
  PolicyRuntimeState,
  PolicyScannerEvidence,
  ValidatedPolicyRuntimeState,
} from "./policy/runtime-state.js";
export {
  secureDefaultPolicyEngine,
  SECURE_DEFAULT_POLICY_HASH,
} from "./policy/secure-default-engine.js";

// Risk
export { riskAggregator, createRiskAggregator } from "./risk/aggregator.js";
export type { RiskAggregationInput, RiskAggregator } from "./risk/aggregator.js";
export { DEFAULT_RISK_POLICY, applyRiskSignal, stateForScore } from "./risk/engine.js";
export type { RiskPolicy, RiskSignal, RiskTransition } from "./risk/engine.js";

// Scanner
export { SCANNER_PERMISSIONS } from "./scanner/manifest.js";
export type { ScannerPermission, PluginManifest } from "./scanner/manifest.js";
export type { SecurityScanner, PluginSecurityScannerDefinition } from "./scanner/scanner.js";
export type {
  SecurityContext,
  PhasePayload,
  ModelOutput,
  ScopedContextView,
} from "./scanner/context.js";
export { buildScopedView } from "./scanner/context.js";
export { defineScanner, definePluginScanner } from "./scanner/define-scanner.js";

// Orchestrator
export { ScannerRegistry } from "./orchestrator/registry.js";
export { runPhase } from "./orchestrator/run-phase.js";
export type {
  RunPhaseResult,
  ScanFailureKind,
  ScannerFailure,
  PhaseTierMetric,
} from "./orchestrator/run-phase.js";
export { runWithDeadline } from "./orchestrator/timeouts.js";
export type { DeadlineResult, DeadlineFailureKind } from "./orchestrator/timeouts.js";
export {
  applySanitizationPipeline,
  applySanitizations,
  applySanitizationSpans,
} from "./orchestrator/sanitize.js";
export type { SanitizationSpan } from "./orchestrator/sanitize.js";
export { DEFAULT_RESOURCE_LIMITS } from "./orchestrator/limits.js";
export type { ResourceLimits } from "./orchestrator/limits.js";

// Trace
export { TRACE_SCHEMA_VERSION, CORE_VERSION, TRACE_EVENT_KINDS } from "./trace/events.js";
export type {
  TraceEventKind,
  TraceEvent,
  TraceDocument,
  EvidenceReference,
} from "./trace/events.js";
export { TraceWriter, redactDeep } from "./trace/writer.js";
export type { TraceSink } from "./trace/writer.js";
export {
  RedactionRegistry,
  DEFAULT_REDACTION_LIMITS,
  hash,
  secretRedactionForms,
} from "./trace/redact.js";
export type { RedactedEvidence, Redactor, RedactionRegistryLimits } from "./trace/redact.js";
export {
  validateTraceEvent,
  validateTraceDocument,
  isCompatibleSchemaVersion,
  schemaVersionMajor,
} from "./trace/validate.js";
export type { TraceValidationResult } from "./trace/validate.js";

// Session accounting
export { SessionBudgetLedger, systemSessionClock } from "./session/budgets.js";
export type { BudgetKind, BudgetSnapshot, BudgetUse, SessionClock } from "./session/budgets.js";

// Adapter
export type { PageObservation, FrameInfo } from "./adapter/observation.js";
export type { BrowserAdapterCapabilities } from "./adapter/capabilities.js";
export type { BrowserAdapter, AdapterEventSink, AdapterEvent } from "./adapter/browser-adapter.js";
export { isUnsafeAdapterAccess } from "./adapter/raw-access.js";
export type { UnsafeAdapterAccess } from "./adapter/raw-access.js";
export { runAdapterConformance, validatePageObservation } from "./adapter/conformance.js";
export type { AdapterConformanceReport, ConformanceCheck } from "./adapter/conformance.js";

// Guard
export { GUARD_ROLES } from "./guard/roles.js";
export type { GuardRole } from "./guard/roles.js";
export type { GuardClassification } from "./guard/classification.js";
export { validateGuardClassification } from "./guard/classification.js";
export type { GuardClassificationRequest, GuardBudget } from "./guard/request.js";
export type { GuardModelProvider } from "./guard/provider.js";
export { DETECTOR_TIERS, TIER_KINDS, kindForTier, defaultTierForKind } from "./guard/tier.js";
export type { DetectorTier } from "./guard/tier.js";
export { runDetectorRouter } from "./guard/router.js";
export type {
  DetectorRouterInput,
  DetectorRouterResult,
  DetectorTierMetric,
  SemanticTierSlot,
  TierSkipReason,
} from "./guard/router.js";
export {
  runGuardProvider,
  guardTokenReservation,
  GuardProviderRuntimeError,
  DEFAULT_GUARD_EXECUTION_LIMITS,
} from "./guard/execution.js";
export type {
  GuardDispatchReservation,
  GuardExecutionConstraints,
  GuardProviderFailureKind,
  GuardProviderOutcome,
} from "./guard/execution.js";

// Network
export { isPrivateNetworkDestination } from "./network/private-network.js";
export { isWithinInternalNetworkRanges } from "./network/private-network.js";
export { isValidInternalNetworkRange } from "./network/private-network.js";
export {
  DEFAULT_DESTINATION_RULES,
  evaluateDestination,
  evaluateRedirectChain,
  isSupportedNetworkScheme,
  destinationOrigin,
} from "./network/destination.js";
export type {
  DestinationRules,
  DestinationEvaluationInput,
  DestinationEvaluation,
  RedirectChainEvaluationInput,
} from "./network/destination.js";
export { NETWORK_INITIATORS } from "./network/initiator.js";
export type { NetworkInitiator } from "./network/initiator.js";
export {
  NETWORK_SURFACES,
  ENFORCEMENT_LEVELS,
  DEFAULT_NETWORK_CAPABILITIES,
} from "./network/capabilities.js";
export type {
  NetworkSurface,
  EnforcementLevel,
  NetworkCapabilities,
} from "./network/capabilities.js";
export type { NetworkMutation, NetworkRequestMetadata } from "./network/mutation.js";
export { NETWORK_VERDICTS } from "./network/decision.js";
export type { NetworkVerdict, NetworkGuardDecision } from "./network/decision.js";
export type { NetworkGuardInput, NetworkGuard } from "./network/guard.js";
export { evaluateNetworkMutation } from "./network/evaluate.js";
export type { NetworkMutationEvaluationInput } from "./network/evaluate.js";
export { correlateNetworkMutation } from "./network/correlate.js";
export type {
  NetworkIntentCorrelation,
  NetworkIntentCorrelationStatus,
} from "./network/correlate.js";
export { validateNetworkMutation, validateNetworkCapabilities } from "./network/validate.js";

// Probe
export { buildProbeScript, PROBE_SCRIPT, DEFAULT_PROBE_OPTIONS } from "./probe/build-probe.js";
export type { ProbeBuildOptions } from "./probe/build-probe.js";
export { PROBE_SCRIPT_TEMPLATE } from "./probe/probe-script.js";
export { PROBE_VERSION, PROBE_CONTRAST_UNSUPPORTED } from "./probe/probe-result.js";
export type {
  ProbeResult,
  ProbeNode,
  ProbeMetadata,
  ProbeLink,
  ProbeTruncation,
} from "./probe/probe-result.js";
export { validateProbeResult } from "./probe/validate.js";

// Session
export { SecuritySession } from "./session/session.js";
export type {
  SecuritySessionInit,
  PerceptionResult,
  BoundAuthorizationResult,
  SessionGuardExecution,
  SessionGuardClassifier,
  SessionGuardScannerFactory,
  TrustedInstructionOptions,
} from "./session/session.js";
export { OpenAgentFence } from "./session/facade.js";
export type { OpenAgentFenceOptions } from "./session/facade.js";
export { resolveApproval } from "./session/approval.js";
export type {
  ApprovalRequest,
  ApprovalDecision,
  ApprovalHandler,
  ApprovalResolutionOptions,
} from "./session/approval.js";
export type { UnsafeAccess } from "./session/unsafe.js";
export type { SessionDecision, SessionEvents } from "./session/events.js";
