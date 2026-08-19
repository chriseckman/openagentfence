import { randomBytes } from "node:crypto";
import type { BrowserAdapter } from "../adapter/browser-adapter.js";
import type { PolicyEngine } from "../policy/engine.js";
import { secureDefaultPolicyEngine } from "../policy/secure-default-engine.js";
import type { GuardModelProvider } from "../guard/provider.js";
import type { VaultAdapter } from "../secrets/vault-adapter.js";
import type { SecurityScanner } from "../scanner/scanner.js";
import { ScannerRegistry } from "../orchestrator/registry.js";
import { RedactionRegistry } from "../trace/redact.js";
import { TraceWriter, type TraceSink } from "../trace/writer.js";
import { validateTaskContract } from "../contracts/task-contract.js";
import { compileTaskContract } from "../envelope/compile.js";
import { DEFAULT_RESOURCE_LIMITS, type ResourceLimits } from "../orchestrator/limits.js";
import { TRACE_SCHEMA_VERSION, CORE_VERSION } from "../trace/events.js";
import type { ApprovalHandler } from "./approval.js";
import { SecuritySession } from "./session.js";

export interface OpenAgentFenceOptions {
  readonly adapter: BrowserAdapter;
  readonly policy?: PolicyEngine;
  readonly scanners?: readonly SecurityScanner[];
  readonly guardModel?: GuardModelProvider;
  readonly vault?: VaultAdapter;
  readonly approvalHandler?: ApprovalHandler;
  readonly trace?: TraceSink;
  readonly limits?: ResourceLimits;
}

/**
 * The firewall facade (PRD §3, ARCHITECTURE §3/§4). The facade accepts only an
 * instantiated `PolicyEngine` (never a file path, ADR-0008) and an instantiated
 * `GuardModelProvider` (never provider options or credentials, ADR-0009).
 */
export class OpenAgentFence {
  private readonly adapter: BrowserAdapter;
  private readonly policy: PolicyEngine;
  private readonly guardModel: GuardModelProvider | undefined;
  private readonly vault: VaultAdapter | undefined;
  private readonly approvalHandler: ApprovalHandler | undefined;
  private readonly traceSink: TraceSink | undefined;
  private readonly registry = new ScannerRegistry();
  private readonly redactor = new RedactionRegistry();
  private readonly limits: ResourceLimits;

  constructor(options: OpenAgentFenceOptions) {
    this.adapter = options.adapter;
    this.policy = options.policy ?? secureDefaultPolicyEngine;
    this.guardModel = options.guardModel;
    this.vault = options.vault;
    this.approvalHandler = options.approvalHandler;
    this.traceSink = options.trace;
    this.limits = options.limits ?? DEFAULT_RESOURCE_LIMITS;
    for (const scanner of options.scanners ?? []) {
      this.registry.register(scanner);
    }
  }

  get scanners(): ScannerRegistry {
    return this.registry;
  }

  /**
   * Start a session for a task. The contract is schema-validated at the trust
   * boundary (TB1), compiled into a secure-default-constrained envelope, and
   * frozen; invalid contracts throw before any adapter call.
   */
  start(contractInput: unknown): SecuritySession {
    const result = validateTaskContract(contractInput);
    if (!result.ok) {
      throw new TypeError(`invalid task contract: ${result.errors.join("; ")}`);
    }
    const contract = result.value;
    const envelope = compileTaskContract(contract);
    const id = randomBytes(8).toString("hex");
    const trace = new TraceWriter(this.redactor);
    if (this.traceSink !== undefined) {
      trace.attach(this.traceSink);
    }
    trace.start({
      sessionId: id,
      task: contract.task,
      policyHash: this.policy.policyHash,
      capabilities: this.adapter.capabilities,
      versions: { schema: TRACE_SCHEMA_VERSION, core: CORE_VERSION },
    });
    return new SecuritySession({
      id,
      adapter: this.adapter,
      contract,
      envelope,
      policy: this.policy,
      registry: this.registry,
      redactor: this.redactor,
      limits: this.limits,
      ...(this.guardModel !== undefined ? { guardModel: this.guardModel } : {}),
      ...(this.vault !== undefined ? { vault: this.vault } : {}),
      ...(this.approvalHandler !== undefined ? { approvalHandler: this.approvalHandler } : {}),
      trace,
    });
  }
}
