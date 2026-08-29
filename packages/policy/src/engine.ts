import {
  ActionSchema,
  ApprovalReceiptSchema,
  CapabilitySchema,
  LeaseSchema,
  type Action,
  type ApprovalReceipt,
  type BrokerErrorCode,
  type Capability,
  type ElementReference,
  type Lease,
  type PolicyDecision,
  type RiskLevel,
  type Scope,
} from "@tabgrant/protocol";

import { hashAction } from "./canonicalize.js";

export interface PreparedActionState {
  readonly prepareId: string;
  readonly actionHash: string;
  readonly stateWitnessHash: string;
}

export interface PolicyContext {
  readonly now: number;
  readonly clientId: string;
  readonly taskId: string;
  readonly browserProfileInstance: string;
  readonly tabId: string;
  readonly documentId: string;
  readonly topLevelOrigin: string;
  readonly audience: string;
  readonly policyVersion: string;
  readonly currentDomEpoch?: number;
  readonly capabilitySignatureVerified: boolean;
  readonly approvalSignatureVerified?: boolean;
  readonly enterpriseAllowed?: boolean;
  readonly rateLimitAllowed?: boolean;
  readonly stateWitnessHash?: string;
  readonly prepared?: PreparedActionState;
}

export interface PolicyEvaluationRequest {
  readonly phase: "prepare" | "commit";
  readonly action: unknown;
  readonly capability: unknown;
  readonly lease: unknown;
  readonly approval?: unknown;
  readonly context: PolicyContext;
}

const RISK_BY_ACTION: Readonly<Record<Action["kind"], RiskLevel>> = {
  "page.a11y.read": "R0",
  "page.screenshot.read": "R0",
  "page.scroll": "R0",
  "page.highlight": "R0",
  "page.click.reversible": "R1",
  "page.form.draft": "R1",
  "page.navigate": "R1",
  "page.form.submit": "R2",
  "content.publish": "R3",
  "message.send": "R3",
  "data.delete": "R3",
  "security.permission.change": "R3",
  "financial.transaction": "R3",
  "security.oauth.consent": "R3",
};

const FIXED_SCOPE_BY_ACTION: Partial<Record<Action["kind"], Scope["kind"]>> = {
  "page.a11y.read": "page.a11y.read",
  "page.screenshot.read": "page.screenshot.read",
  "page.scroll": "page.scroll",
  "page.highlight": "page.highlight",
  "page.click.reversible": "page.click.reversible",
  "page.form.draft": "page.form.draft",
};

const R3_REQUIREMENTS = ["MANUAL_USER_COMPLETION", "STATE_WITNESS", "IDEMPOTENCY_KEY"] as const;
const R2_REQUIREMENTS = [
  "TRUSTED_USER_PRESENCE",
  "ONE_TIME_RECEIPT",
  "STATE_WITNESS",
  "IDEMPOTENCY_KEY",
] as const;

function actionKindOf(action: unknown): string {
  if (typeof action !== "object" || action === null) return "unknown";
  const kind = (action as Record<string, unknown>)["kind"];
  return typeof kind === "string" ? kind : "unknown";
}

function forbiddenCodeForKind(kind: string): BrokerErrorCode | undefined {
  const lower = kind.toLowerCase();
  if (lower.includes("cookie")) return "COOKIE_ACCESS_FORBIDDEN";
  if (
    lower.includes("password") ||
    lower.includes("credential.read") ||
    lower.includes("token.read") ||
    lower.includes("secret") ||
    lower.includes("otp") ||
    lower.includes("passkey")
  ) {
    return "SECRET_ACCESS_FORBIDDEN";
  }
  if (lower.includes("cdp") || lower.includes("devtools") || lower.includes("debugger")) {
    return "CDP_ACCESS_FORBIDDEN";
  }
  if (
    lower.includes("javascript") ||
    lower.includes("script.execute") ||
    lower.includes("eval") ||
    lower.includes("shell") ||
    lower.includes("native.command")
  ) {
    return "ARBITRARY_CODE_FORBIDDEN";
  }
  return undefined;
}

function deny(
  actionKind: string,
  risk: RiskLevel,
  errorCode: BrokerErrorCode,
  reason: string,
): PolicyDecision {
  return { outcome: "DENY", risk, actionKind, errorCode, reason, requirements: [] };
}

function allow(action: Action, risk: RiskLevel, reason: string): PolicyDecision {
  return {
    outcome: "ALLOW",
    risk,
    actionKind: action.kind,
    actionHash: hashAction(action),
    reason,
    requirements: [],
  };
}

function allowPrepare(action: Action, risk: "R2" | "R3"): PolicyDecision {
  return {
    outcome: "ALLOW_PREPARE",
    risk,
    actionKind: action.kind,
    actionHash: hashAction(action),
    reason:
      risk === "R2"
        ? "action may be prepared but requires a bound one-time approval before commit"
        : "v0.1 permits preview only; the user must complete this action manually",
    requirements: risk === "R2" ? [...R2_REQUIREMENTS] : [...R3_REQUIREMENTS],
  };
}

function contextMismatch(capability: Capability, lease: Lease, context: PolicyContext): boolean {
  const expected = [
    [capability.clientId, context.clientId],
    [capability.taskId, context.taskId],
    [capability.browserProfileInstance, context.browserProfileInstance],
    [capability.tabId, context.tabId],
    [capability.documentId, context.documentId],
    [capability.topLevelOrigin, context.topLevelOrigin],
    [capability.audience, context.audience],
    [capability.policyVersion, context.policyVersion],
    [lease.capabilityId, capability.capabilityId],
    [lease.clientId, context.clientId],
    [lease.taskId, context.taskId],
    [lease.browserProfileInstance, context.browserProfileInstance],
    [lease.tabId, context.tabId],
    [lease.documentId, context.documentId],
    [lease.topLevelOrigin, context.topLevelOrigin],
  ];
  return expected.some(([actual, wanted]) => actual !== wanted);
}

function validateGrant(
  capability: Capability,
  lease: Lease,
  context: PolicyContext,
  actionKind: string,
): PolicyDecision | undefined {
  if (!context.capabilitySignatureVerified) {
    return deny(actionKind, "R4", "CAPABILITY_INVALID", "capability signature was not verified");
  }
  if (context.enterpriseAllowed !== true) {
    return deny(
      actionKind,
      "R4",
      "ENTERPRISE_POLICY_DENIED",
      "enterprise policy did not explicitly allow access",
    );
  }
  if (context.rateLimitAllowed !== true) {
    return deny(
      actionKind,
      "R4",
      "RATE_LIMITED",
      "action budget or rate limit was not explicitly available",
    );
  }
  if (contextMismatch(capability, lease, context)) {
    return deny(
      actionKind,
      "R4",
      "CAPABILITY_CONTEXT_MISMATCH",
      "client, task, tab, document, origin, or audience changed",
    );
  }
  if (capability.issuedAt > context.now || capability.expiresAt <= context.now) {
    return deny(actionKind, "R4", "CAPABILITY_EXPIRED", "capability is not currently valid");
  }
  if (
    lease.issuedAt < capability.issuedAt ||
    lease.expiresAt > capability.expiresAt ||
    lease.idleTimeoutMs > capability.idleTimeoutMs ||
    lease.remainingUses > capability.useLimit
  ) {
    return deny(
      actionKind,
      "R4",
      "CAPABILITY_INVALID",
      "lease expands the capability lifetime, idle timeout, or use budget",
    );
  }
  if (lease.state === "revoked") {
    return deny(actionKind, "R4", "LEASE_REVOKED", "lease has been revoked");
  }
  if (lease.state !== "active" || lease.expiresAt <= context.now) {
    return deny(actionKind, "R4", "LEASE_EXPIRED", "lease is not active");
  }
  if (lease.lastUsedAt + lease.idleTimeoutMs <= context.now || lease.remainingUses <= 0) {
    return deny(actionKind, "R4", "LEASE_EXPIRED", "lease idle timeout or use limit was reached");
  }
  return undefined;
}

function hasFixedScope(capability: Capability, kind: Scope["kind"]): boolean {
  return capability.scopes.some((scope) => scope.kind === kind);
}

function hasPrepareScope(capability: Capability, actionKind: string): boolean {
  return capability.scopes.some(
    (scope) => scope.kind === "action.prepare" && scope.actionTypes.includes(actionKind),
  );
}

function hasNavigationScope(
  capability: Capability,
  action: Extract<Action, { kind: "page.navigate" }>,
): boolean {
  const destinationOrigin = new URL(action.url).origin;
  if (
    destinationOrigin === capability.topLevelOrigin &&
    capability.scopes.some((scope) => scope.kind === "page.navigate.same_origin")
  ) {
    return true;
  }
  return capability.scopes.some(
    (scope) => scope.kind === "page.navigate.allowed_origin" && scope.origin === destinationOrigin,
  );
}

function referencesFor(action: Action): ElementReference[] {
  switch (action.kind) {
    case "page.highlight":
    case "page.click.reversible":
    case "page.form.submit":
      return [action.target];
    case "page.form.draft":
      return action.fields.map((field) => field.target);
    default:
      return [];
  }
}

function staleReference(action: Action, context: PolicyContext): boolean {
  return referencesFor(action).some(
    (reference) =>
      reference.expiresAt <= context.now ||
      reference.issuedAt > context.now ||
      reference.tabId !== context.tabId ||
      reference.documentId !== context.documentId ||
      reference.topLevelOrigin !== context.topLevelOrigin ||
      (context.currentDomEpoch !== undefined && reference.domEpoch !== context.currentDomEpoch),
  );
}

function dataClassAllowed(action: Action, capability: Capability): boolean {
  if (action.kind !== "page.form.draft") return true;
  return action.fields.every((field) => capability.dataClasses.includes(field.dataClass));
}

function requiredScopePresent(action: Action, capability: Capability): boolean {
  if (action.kind === "page.navigate") return hasNavigationScope(capability, action);
  if (RISK_BY_ACTION[action.kind] === "R2" || RISK_BY_ACTION[action.kind] === "R3") {
    return hasPrepareScope(capability, action.kind);
  }
  const required = FIXED_SCOPE_BY_ACTION[action.kind];
  return required !== undefined && hasFixedScope(capability, required);
}

function validateApproval(
  approval: ApprovalReceipt | undefined,
  action: Action,
  capability: Capability,
  context: PolicyContext,
): PolicyDecision | undefined {
  if (context.prepared === undefined) {
    return deny(
      action.kind,
      "R2",
      "PREPARE_REQUIRED",
      "commit is not bound to a stored prepared action",
    );
  }
  if (approval === undefined || context.approvalSignatureVerified !== true) {
    return deny(action.kind, "R2", "APPROVAL_REQUIRED", "a verified approval receipt is required");
  }
  if (approval.consumedAt !== undefined) {
    return deny(action.kind, "R2", "APPROVAL_REPLAYED", "approval receipt was already consumed");
  }
  if (approval.issuedAt > context.now || approval.expiresAt <= context.now) {
    return deny(action.kind, "R2", "APPROVAL_EXPIRED", "approval receipt is not currently valid");
  }
  const actionHash = hashAction(action);
  const expectedPairs = [
    [approval.prepareId, context.prepared.prepareId],
    [approval.actionHash, actionHash],
    [approval.actionHash, context.prepared.actionHash],
    [approval.stateWitnessHash, context.prepared.stateWitnessHash],
    [approval.stateWitnessHash, context.stateWitnessHash],
    [approval.clientId, context.clientId],
    [approval.taskId, context.taskId],
    [approval.tabId, context.tabId],
    [approval.documentId, context.documentId],
    [approval.topLevelOrigin, context.topLevelOrigin],
    [approval.policyVersion, capability.policyVersion],
  ];
  if (expectedPairs.some(([actual, expected]) => expected === undefined || actual !== expected)) {
    return deny(
      action.kind,
      "R2",
      "STATE_CHANGED",
      "prepared action, state witness, or approval context changed",
    );
  }
  if (
    approval.userPresence.verifiedAt < approval.issuedAt ||
    approval.userPresence.verifiedAt > approval.expiresAt
  ) {
    return deny(
      action.kind,
      "R2",
      "APPROVAL_INVALID",
      "user-presence proof is outside approval lifetime",
    );
  }
  return undefined;
}

export function evaluatePolicy(request: PolicyEvaluationRequest): PolicyDecision {
  const actionKind = actionKindOf(request.action);
  const forbiddenCode = forbiddenCodeForKind(actionKind);
  if (forbiddenCode !== undefined) {
    return deny(actionKind, "R4", forbiddenCode, "the requested browser authority is prohibited");
  }

  const actionResult = ActionSchema.safeParse(request.action);
  if (!actionResult.success) {
    return deny(
      actionKind,
      "R4",
      "UNKNOWN_ACTION",
      "unknown or malformed actions are denied by default",
    );
  }
  const action = actionResult.data;

  const capabilityResult = CapabilitySchema.safeParse(request.capability);
  if (!capabilityResult.success) {
    return deny(
      action.kind,
      "R4",
      "CAPABILITY_INVALID",
      "capability did not pass strict schema validation",
    );
  }
  const leaseResult = LeaseSchema.safeParse(request.lease);
  if (!leaseResult.success) {
    return deny(
      action.kind,
      "R4",
      "CAPABILITY_INVALID",
      "lease did not pass strict schema validation",
    );
  }
  const capability = capabilityResult.data;
  const lease = leaseResult.data;

  const grantFailure = validateGrant(capability, lease, request.context, action.kind);
  if (grantFailure !== undefined) return grantFailure;

  if (staleReference(action, request.context)) {
    return deny(
      action.kind,
      "R4",
      "STALE_ELEMENT_REFERENCE",
      "element reference is stale or belongs to a different context",
    );
  }
  if (!dataClassAllowed(action, capability)) {
    return deny(
      action.kind,
      "R4",
      "CAPABILITY_SCOPE_DENIED",
      "form data class exceeds the capability grant",
    );
  }
  if (!requiredScopePresent(action, capability)) {
    return deny(action.kind, "R4", "CAPABILITY_SCOPE_DENIED", "required action scope is absent");
  }

  const risk = RISK_BY_ACTION[action.kind];
  if (risk === "R3") {
    return request.phase === "prepare"
      ? allowPrepare(action, "R3")
      : deny(action.kind, "R3", "RISK_NOT_SUPPORTED", "R3 commit is not supported in v0.1");
  }
  if (risk === "R2") {
    if (request.phase === "prepare") return allowPrepare(action, "R2");
    const approvalResult = ApprovalReceiptSchema.safeParse(request.approval);
    const approval = approvalResult.success ? approvalResult.data : undefined;
    const approvalFailure = validateApproval(approval, action, capability, request.context);
    if (approvalFailure !== undefined) return approvalFailure;
    return allow(action, "R2", "bound one-time approval and state witness validated");
  }
  if (request.phase === "commit") {
    return deny(
      action.kind,
      risk,
      "PREPARE_REQUIRED",
      "R0/R1 actions execute through prepare evaluation only",
    );
  }
  return allow(action, risk, "capability, lease, context, reference, and scope validated");
}

export class PolicyAuthorizationError extends Error {
  readonly decision: PolicyDecision;

  constructor(decision: PolicyDecision) {
    super(`${decision.errorCode ?? "DENY"}: ${decision.reason}`);
    this.name = "PolicyAuthorizationError";
    this.decision = decision;
  }
}

export function assertAuthorized(request: PolicyEvaluationRequest): PolicyDecision {
  const decision = evaluatePolicy(request);
  if (decision.outcome === "DENY") throw new PolicyAuthorizationError(decision);
  return decision;
}
