import { randomUUID } from "node:crypto";
import { evaluatePolicy } from "@tabgrant/policy";
import {
  OriginSchema,
  type Action,
  type Capability,
  type Lease as PolicyLease,
} from "@tabgrant/protocol";
import { z } from "zod";
import type { AuthHello } from "./auth.js";
import type { AuditLogger } from "./audit.js";
import {
  ACCESS_PENDING_GLOBAL_LIMIT,
  ACCESS_PENDING_PER_SESSION_LIMIT,
  ACCESS_REQUEST_RATE_WINDOW_MS,
  ACCESS_REQUEST_RECORD_LIMIT,
  ACCESS_REQUESTS_GLOBAL_WINDOW,
  ACCESS_REQUESTS_PER_SESSION_WINDOW,
  ACCESS_REQUEST_TTL_MS,
  DEFAULT_LEASE_TTL_MS,
  IMPLEMENTED_SCOPES,
  LEASE_COMMANDS_PER_WINDOW,
  LEASE_COMMAND_WINDOW_MS,
  LEASE_EGRESS_BUDGET_BYTES,
  LEASE_IDLE_TIMEOUT_MS,
  LEASE_MAX_IN_FLIGHT,
  LEASE_RECORD_LIMIT,
  LEASE_USE_LIMIT,
  MAX_LEASE_TTL_MS,
  SNAPSHOT_MAX_RESULT_BYTES,
  STATE_MAINTENANCE_INTERVAL_MS,
  TERMINAL_RECORD_RETENTION_MS,
  type ImplementedScope,
} from "./constants.js";
import type { CapabilityIssuer } from "./capability.js";
import { BrokerRpcError, type RpcPeer } from "./wire.js";

const ScopeSchema = z.enum(IMPLEMENTED_SCOPES);
const SafeOriginSchema = OriginSchema;

const AccessRequestParamsSchema = z
  .object({
    scopes: z.array(ScopeSchema).min(1).max(IMPLEMENTED_SCOPES.length),
    reason: z.string().trim().min(1).max(240),
    declaredModelProvider: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[a-zA-Z0-9._:-]+$/)
      .optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.scopes.includes("data.egress.model") && value.declaredModelProvider === undefined) {
      context.addIssue({
        code: "custom",
        message: "Model data release requires a declared provider label.",
      });
    }
  });

const RegisterBrowserParamsSchema = z
  .object({
    browserInstanceId: z.string().uuid(),
    extensionId: z.string().regex(/^[a-p]{32}$/),
    browserName: z.string().min(1).max(64),
    browserVersion: z.string().min(1).max(64),
  })
  .strict();

const GrantParamsSchema = z
  .object({
    requestId: z.string().uuid(),
    browserInstanceId: z.string().uuid(),
    tabId: z.number().int().nonnegative(),
    documentId: z.string().min(1).max(128),
    origin: SafeOriginSchema,
    url: z.string().url().max(2_048),
    title: z.string().max(256),
    scopes: z.array(ScopeSchema).min(1).max(IMPLEMENTED_SCOPES.length),
    ttlSeconds: z
      .number()
      .int()
      .min(30)
      .max(MAX_LEASE_TTL_MS / 1_000)
      .optional(),
  })
  .strict();

const LeaseIdParamsSchema = z.object({ leaseId: z.string().uuid() }).strict();

const SnapshotParamsSchema = z
  .object({
    leaseId: z.string().uuid(),
    maxNodes: z.number().int().min(1).max(500).default(200),
  })
  .strict();

const HighlightParamsSchema = z
  .object({
    leaseId: z.string().uuid(),
    ref: z.string().min(1).max(64),
    epoch: z.number().int().nonnegative(),
  })
  .strict();

const ScrollParamsSchema = z
  .object({
    leaseId: z.string().uuid(),
    deltaY: z.number().int().min(-2_000).max(2_000),
  })
  .strict();

const NavigateParamsSchema = z
  .object({
    leaseId: z.string().uuid(),
    url: z.string().url().max(2_048),
  })
  .strict();

interface ConnectionContext {
  readonly auth: AuthHello;
  readonly peer: RpcPeer;
  browserInstanceId?: string;
}

type AccessStatus = "pending" | "granted" | "denied" | "expired" | "revoked";

interface AccessRequest {
  readonly requestId: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly taskId: string;
  readonly scopes: ImplementedScope[];
  readonly reason: string;
  readonly declaredModelProvider?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  status: AccessStatus;
  terminalAt?: number;
  leaseId?: string;
}

interface FixedWindow {
  startedAt: number;
  count: number;
}

interface Lease {
  readonly leaseId: string;
  readonly requestId: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly taskId: string;
  readonly browserInstanceId: string;
  readonly tabId: number;
  readonly documentId: string;
  readonly origin: string;
  readonly url: string;
  readonly title: string;
  readonly scopes: ImplementedScope[];
  readonly declaredModelProvider?: string;
  readonly capability: Capability;
  readonly policyLease: PolicyLease;
  readonly issuedAt: number;
  readonly expiresAt: number;
  lastUsedAt: number;
  inFlight: number;
  commandWindowStartedAt: number;
  commandsInWindow: number;
  remainingEgressBytes: number;
  revokedAt?: number;
  revokeReason?: string;
}

interface BrowserConnection {
  readonly context: ConnectionContext;
  readonly browserName: string;
  readonly browserVersion: string;
  readonly extensionId: string;
}

export class BrokerState {
  private readonly accessRequests = new Map<string, AccessRequest>();
  private readonly leases = new Map<string, Lease>();
  private readonly browsers = new Map<string, BrowserConnection>();
  private readonly sessionIds = new WeakMap<ConnectionContext, string>();
  private readonly accessRequestWindows = new WeakMap<ConnectionContext, FixedWindow>();
  private globalAccessRequestWindow: FixedWindow = { startedAt: 0, count: 0 };
  private nextMaintenanceAt = 0;

  public constructor(
    private readonly audit: AuditLogger,
    private readonly capabilityIssuer: CapabilityIssuer,
    private readonly now: () => number = Date.now,
  ) {}

  public createContext(auth: AuthHello, peer: RpcPeer): ConnectionContext {
    const context: ConnectionContext = { auth, peer };
    this.sessionIds.set(context, randomUUID());
    return context;
  }

  public async handle(
    context: ConnectionContext,
    method: string,
    params: unknown,
  ): Promise<unknown> {
    this.maintainState();
    if (method === "broker.status") {
      return this.status(context);
    }

    if (context.auth.role === "browser") {
      return this.handleBrowser(context, method, params);
    }
    return this.handleAgent(context, method, params);
  }

  public async disconnected(context: ConnectionContext): Promise<void> {
    if (context.browserInstanceId !== undefined) {
      this.browsers.delete(context.browserInstanceId);
      for (const lease of this.leases.values()) {
        if (
          lease.browserInstanceId === context.browserInstanceId &&
          lease.revokedAt === undefined
        ) {
          this.revokeLease(lease, "BROWSER_DISCONNECTED");
        }
      }
      await this.audit.record({ event: "browser.disconnected", outcome: "info" });
      return;
    }
    for (const request of this.accessRequests.values()) {
      if (request.sessionId === this.sessionId(context) && request.status === "pending") {
        request.status = "revoked";
        request.terminalAt = this.now();
      }
    }
    for (const lease of this.leases.values()) {
      if (lease.sessionId === this.sessionId(context) && lease.revokedAt === undefined) {
        this.revokeLease(lease, "AGENT_DISCONNECTED");
      }
    }
  }

  private async handleAgent(
    context: ConnectionContext,
    method: string,
    params: unknown,
  ): Promise<unknown> {
    switch (method) {
      case "access.request":
        return this.requestAccess(context, params);
      case "access.status":
        return this.accessStatus(context);
      case "access.revoke":
        return this.agentRevoke(context, params);
      case "browser.tabs.list":
        return this.listGrantedTabs(context);
      case "browser.snapshot":
        return this.execute(
          context,
          "snapshot",
          "page.a11y.read",
          SnapshotParamsSchema.parse(params),
        );
      case "browser.highlight":
        return this.execute(
          context,
          "highlight",
          "page.highlight",
          HighlightParamsSchema.parse(params),
        );
      case "browser.scroll":
        return this.execute(context, "scroll", "page.scroll", ScrollParamsSchema.parse(params));
      case "browser.navigate":
        return this.navigate(context, NavigateParamsSchema.parse(params));
      default:
        await this.audit.record({
          event: "method.denied",
          outcome: "denied",
          clientId: context.auth.clientId,
          taskId: context.auth.taskId,
          method,
          reasonCode: "UNKNOWN_METHOD",
        });
        throw new BrokerRpcError("UNKNOWN_METHOD", `Unsupported agent method: ${method}`);
    }
  }

  private async handleBrowser(
    context: ConnectionContext,
    method: string,
    params: unknown,
  ): Promise<unknown> {
    switch (method) {
      case "browser.register":
        return this.registerBrowser(context, params);
      case "access.pending.list":
        return this.listPendingRequests();
      case "access.grant":
        return this.grantAccess(context, params);
      case "access.deny":
        return this.browserDeny(context, params);
      case "access.revoke":
        return this.browserRevoke(context, params);
      default:
        throw new BrokerRpcError("UNKNOWN_METHOD", `Unsupported browser method: ${method}`);
    }
  }

  private status(context: ConnectionContext): unknown {
    return {
      version: "0.1.0",
      protocolVersion: 1,
      role: context.auth.role,
      clientId: context.auth.clientId,
      taskId: context.auth.taskId,
      browserConnected: this.browsers.size > 0,
      killSwitchActive: false,
    };
  }

  private async requestAccess(context: ConnectionContext, params: unknown): Promise<unknown> {
    const parsed = AccessRequestParamsSchema.parse(params);
    this.expireRecords();
    this.reserveAccessRequestRate(context);
    const sessionId = this.sessionId(context);
    let sessionPending = 0;
    let globalPending = 0;
    for (const request of this.accessRequests.values()) {
      if (request.status !== "pending") continue;
      globalPending += 1;
      if (request.sessionId === sessionId) sessionPending += 1;
    }
    if (sessionPending >= ACCESS_PENDING_PER_SESSION_LIMIT) {
      throw new BrokerRpcError(
        "SESSION_PENDING_LIMIT",
        `A connection may have at most ${ACCESS_PENDING_PER_SESSION_LIMIT} pending access requests.`,
      );
    }
    if (globalPending >= ACCESS_PENDING_GLOBAL_LIMIT) {
      throw new BrokerRpcError(
        "GLOBAL_PENDING_LIMIT",
        `The broker may have at most ${ACCESS_PENDING_GLOBAL_LIMIT} pending access requests.`,
      );
    }
    this.ensureAccessRequestCapacity();
    const request: AccessRequest = {
      requestId: randomUUID(),
      sessionId,
      clientId: context.auth.clientId,
      taskId: context.auth.taskId,
      scopes: [...new Set(parsed.scopes)],
      reason: parsed.reason,
      ...(parsed.declaredModelProvider === undefined
        ? {}
        : { declaredModelProvider: parsed.declaredModelProvider }),
      createdAt: this.now(),
      expiresAt: this.now() + ACCESS_REQUEST_TTL_MS,
      status: "pending",
    };
    this.accessRequests.set(request.requestId, request);
    for (const browser of this.browsers.values()) {
      browser.context.peer.sendEvent("access.requested", this.publicRequest(request));
    }
    await this.audit.record({
      event: "access.requested",
      outcome: "info",
      clientId: request.clientId,
      taskId: request.taskId,
    });
    return this.publicRequest(request);
  }

  private accessStatus(context: ConnectionContext): unknown {
    this.expireRecords();
    return {
      requests: [...this.accessRequests.values()]
        .filter((request) => this.belongsTo(context, request))
        .map((request) => this.publicRequest(request)),
      leases: [...this.leases.values()]
        .filter((lease) => this.belongsTo(context, lease))
        .map((lease) => this.publicLease(lease)),
    };
  }

  private async agentRevoke(context: ConnectionContext, params: unknown): Promise<unknown> {
    const { leaseId } = LeaseIdParamsSchema.parse(params);
    const lease = this.requireOwnedLease(context, leaseId, false);
    this.revokeLease(lease, "AGENT_REVOKED");
    await this.audit.record({
      event: "access.revoked",
      outcome: "info",
      clientId: lease.clientId,
      taskId: lease.taskId,
      leaseId,
      origin: lease.origin,
    });
    return { revoked: true, leaseId };
  }

  private listGrantedTabs(context: ConnectionContext): unknown {
    this.expireRecords();
    return {
      tabs: [...this.leases.values()]
        .filter((lease) => this.belongsTo(context, lease) && this.isLeaseActive(lease))
        .map((lease) => ({
          leaseId: lease.leaseId,
          tabId: lease.tabId,
          origin: lease.origin,
          url: redactUrl(lease.url),
          title: lease.title,
          scopes: lease.scopes,
          expiresAt: new Date(lease.expiresAt).toISOString(),
          remainingUses: lease.policyLease.remainingUses,
          remainingEgressBytes: lease.remainingEgressBytes,
          inFlight: lease.inFlight,
        })),
    };
  }

  private registerBrowser(context: ConnectionContext, params: unknown): unknown {
    const parsed = RegisterBrowserParamsSchema.parse(params);
    context.browserInstanceId = parsed.browserInstanceId;
    this.browsers.set(parsed.browserInstanceId, {
      context,
      browserName: parsed.browserName,
      browserVersion: parsed.browserVersion,
      extensionId: parsed.extensionId,
    });
    return { registered: true, pending: this.listPendingRequests() };
  }

  private listPendingRequests(): unknown {
    this.expireRecords();
    return {
      requests: [...this.accessRequests.values()]
        .filter((request) => request.status === "pending")
        .slice(0, ACCESS_PENDING_GLOBAL_LIMIT)
        .map((request) => this.publicRequest(request)),
    };
  }

  private async grantAccess(context: ConnectionContext, params: unknown): Promise<unknown> {
    const parsed = GrantParamsSchema.parse(params);
    if (context.browserInstanceId !== parsed.browserInstanceId) {
      throw new BrokerRpcError(
        "BROWSER_ID_MISMATCH",
        "Browser instance does not match the authenticated connection.",
      );
    }
    const request = this.accessRequests.get(parsed.requestId);
    if (request === undefined || request.status !== "pending") {
      throw new BrokerRpcError(
        "ACCESS_REQUEST_NOT_PENDING",
        "Access request is missing or no longer pending.",
      );
    }
    if (request.expiresAt <= this.now()) {
      request.status = "expired";
      request.terminalAt = this.now();
      throw new BrokerRpcError("ACCESS_REQUEST_EXPIRED", "Access request expired.");
    }
    const requested = new Set(request.scopes);
    if (parsed.scopes.some((scope) => !requested.has(scope))) {
      throw new BrokerRpcError(
        "SCOPE_ESCALATION",
        "Granted scopes must be a subset of requested scopes.",
      );
    }
    const actualUrl = new URL(parsed.url);
    if (actualUrl.origin !== parsed.origin || !["http:", "https:"].includes(actualUrl.protocol)) {
      throw new BrokerRpcError("ORIGIN_MISMATCH", "Tab URL does not match the granted origin.");
    }
    this.ensureLeaseCapacity();

    const issuedAt = this.now();
    const expiresAt =
      issuedAt +
      Math.min((parsed.ttlSeconds ?? DEFAULT_LEASE_TTL_MS / 1_000) * 1_000, MAX_LEASE_TTL_MS);
    const capability = this.capabilityIssuer.issue({
      clientId: request.clientId,
      taskId: request.taskId,
      browserInstanceId: parsed.browserInstanceId,
      tabId: parsed.tabId,
      documentId: parsed.documentId,
      origin: parsed.origin,
      scopes: [...new Set(parsed.scopes)],
      ...(request.declaredModelProvider === undefined
        ? {}
        : { declaredModelProvider: request.declaredModelProvider }),
      issuedAt,
      expiresAt,
      useLimit: LEASE_USE_LIMIT,
    });
    const policyLease: PolicyLease = {
      version: "0.1",
      leaseId: randomUUID(),
      capabilityId: capability.capabilityId,
      clientId: request.clientId,
      taskId: request.taskId,
      browserProfileInstance: parsed.browserInstanceId,
      tabId: String(parsed.tabId),
      documentId: parsed.documentId,
      topLevelOrigin: parsed.origin,
      state: "active",
      issuedAt,
      expiresAt,
      lastUsedAt: issuedAt,
      idleTimeoutMs: LEASE_IDLE_TIMEOUT_MS,
      remainingUses: capability.useLimit,
    };
    const lease: Lease = {
      leaseId: policyLease.leaseId,
      requestId: request.requestId,
      sessionId: request.sessionId,
      clientId: request.clientId,
      taskId: request.taskId,
      browserInstanceId: parsed.browserInstanceId,
      tabId: parsed.tabId,
      documentId: parsed.documentId,
      origin: parsed.origin,
      url: parsed.url,
      title: parsed.title,
      scopes: [...new Set(parsed.scopes)],
      ...(request.declaredModelProvider === undefined
        ? {}
        : { declaredModelProvider: request.declaredModelProvider }),
      capability,
      policyLease,
      issuedAt,
      expiresAt,
      lastUsedAt: issuedAt,
      inFlight: 0,
      commandWindowStartedAt: issuedAt,
      commandsInWindow: 0,
      remainingEgressBytes: parsed.scopes.includes("data.egress.model")
        ? LEASE_EGRESS_BUDGET_BYTES
        : 0,
    };
    request.status = "granted";
    request.terminalAt = this.now();
    request.leaseId = lease.leaseId;
    this.leases.set(lease.leaseId, lease);
    await this.audit.record({
      event: "access.granted",
      outcome: "allowed",
      clientId: lease.clientId,
      taskId: lease.taskId,
      leaseId: lease.leaseId,
      origin: lease.origin,
    });
    return this.publicLease(lease);
  }

  private async browserDeny(_context: ConnectionContext, params: unknown): Promise<unknown> {
    const parsed = z.object({ requestId: z.string().uuid() }).strict().parse(params);
    const request = this.accessRequests.get(parsed.requestId);
    if (request === undefined || request.status !== "pending") {
      throw new BrokerRpcError(
        "ACCESS_REQUEST_NOT_PENDING",
        "Access request is missing or no longer pending.",
      );
    }
    request.status = "denied";
    request.terminalAt = this.now();
    await this.audit.record({
      event: "access.denied",
      outcome: "denied",
      clientId: request.clientId,
      taskId: request.taskId,
    });
    return { denied: true, requestId: request.requestId };
  }

  private async browserRevoke(context: ConnectionContext, params: unknown): Promise<unknown> {
    const parsed = z
      .object({ leaseId: z.string().uuid(), reason: z.string().min(1).max(64) })
      .strict()
      .parse(params);
    const lease = this.leases.get(parsed.leaseId);
    if (lease === undefined || lease.browserInstanceId !== context.browserInstanceId) {
      throw new BrokerRpcError("LEASE_NOT_FOUND", "Lease is not owned by this browser instance.");
    }
    this.revokeLease(lease, parsed.reason);
    await this.audit.record({
      event: "access.revoked",
      outcome: "info",
      clientId: lease.clientId,
      taskId: lease.taskId,
      leaseId: lease.leaseId,
      origin: lease.origin,
      reasonCode: parsed.reason,
    });
    return { revoked: true, leaseId: lease.leaseId };
  }

  private async navigate(
    context: ConnectionContext,
    params: z.infer<typeof NavigateParamsSchema>,
  ): Promise<unknown> {
    const lease = this.requireOwnedLease(context, params.leaseId);
    this.requireScope(lease, "page.navigate.same_origin");
    const destination = new URL(params.url);
    if (
      destination.origin !== lease.origin ||
      !["http:", "https:"].includes(destination.protocol)
    ) {
      throw new BrokerRpcError("ORIGIN_CHANGED", "Navigation is limited to the granted origin.");
    }
    return this.executeWithLease(lease, "navigate", { url: destination.toString() });
  }

  private async execute(
    context: ConnectionContext,
    command: "snapshot" | "highlight" | "scroll",
    scope: ImplementedScope,
    params: { leaseId: string } & Record<string, unknown>,
  ): Promise<unknown> {
    const lease = this.requireOwnedLease(context, params.leaseId);
    this.requireScope(lease, scope);
    if (command === "snapshot") {
      this.requireScope(lease, "data.egress.model");
    }
    const args: Record<string, unknown> = { ...params };
    delete args.leaseId;
    return this.executeWithLease(lease, command, args);
  }

  private async executeWithLease(
    lease: Lease,
    command: string,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const browser = this.browsers.get(lease.browserInstanceId);
    if (browser === undefined) {
      this.revokeLease(lease, "BROWSER_DISCONNECTED");
      throw new BrokerRpcError("BROWSER_DISCONNECTED", "The granted browser is disconnected.");
    }
    try {
      this.authorizeCommand(lease, command, args);
      this.reserveCommand(lease);
    } catch (error) {
      await this.auditCommandDenied(lease, command, error);
      throw error;
    }

    let reservedEgressBytes = 0;
    try {
      const result = await browser.context.peer.request("browser.execute", {
        command,
        lease: {
          leaseId: lease.leaseId,
          tabId: lease.tabId,
          documentId: lease.documentId,
          origin: lease.origin,
          scopes: lease.scopes,
          expiresAt: lease.expiresAt,
        },
        args,
      });
      if (!this.isLeaseActive(lease)) {
        throw new BrokerRpcError(
          lease.revokeReason ?? "LEASE_REVOKED",
          "The lease was revoked before the command result could be returned.",
        );
      }
      if (command === "snapshot") {
        reservedEgressBytes = this.reserveSnapshotEgress(lease, result);
      }
      await this.audit.record({
        event: "browser.command",
        outcome: "allowed",
        clientId: lease.clientId,
        taskId: lease.taskId,
        leaseId: lease.leaseId,
        origin: lease.origin,
        method: command,
      });
      return result;
    } catch (error) {
      if (reservedEgressBytes > 0) {
        lease.remainingEgressBytes += reservedEgressBytes;
      }
      await this.auditCommandDenied(lease, command, error);
      throw error;
    } finally {
      lease.inFlight -= 1;
      if (lease.policyLease.remainingUses <= 0 && lease.inFlight === 0) {
        this.revokeLease(lease, "USE_LIMIT_EXHAUSTED");
      }
    }
  }

  private reserveCommand(lease: Lease): void {
    const now = this.now();
    if (lease.inFlight >= LEASE_MAX_IN_FLIGHT) {
      throw new BrokerRpcError(
        "LEASE_CONCURRENCY_LIMIT",
        `A lease permits at most ${LEASE_MAX_IN_FLIGHT} in-flight commands.`,
      );
    }
    if (now - lease.commandWindowStartedAt >= LEASE_COMMAND_WINDOW_MS) {
      lease.commandWindowStartedAt = now;
      lease.commandsInWindow = 0;
    }
    if (lease.commandsInWindow >= LEASE_COMMANDS_PER_WINDOW) {
      throw new BrokerRpcError(
        "LEASE_RATE_LIMIT",
        `A lease permits at most ${LEASE_COMMANDS_PER_WINDOW} commands per minute.`,
      );
    }
    if (lease.policyLease.remainingUses <= 0) {
      throw new BrokerRpcError("USE_LIMIT_EXHAUSTED", "The lease command budget is exhausted.");
    }

    lease.inFlight += 1;
    lease.commandsInWindow += 1;
    lease.policyLease.remainingUses -= 1;
    lease.lastUsedAt = now;
    lease.policyLease.lastUsedAt = now;
  }

  private reserveSnapshotEgress(lease: Lease, result: unknown): number {
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(result);
    } catch {
      throw new BrokerRpcError(
        "INVALID_BROWSER_RESPONSE",
        "The browser snapshot result is not JSON serializable.",
      );
    }
    if (serialized === undefined) {
      throw new BrokerRpcError(
        "INVALID_BROWSER_RESPONSE",
        "The browser snapshot result is not a JSON value.",
      );
    }
    const bytes = Buffer.byteLength(serialized, "utf8");
    if (bytes > SNAPSHOT_MAX_RESULT_BYTES) {
      throw new BrokerRpcError(
        "SNAPSHOT_TOO_LARGE",
        `Snapshot result exceeds the ${SNAPSHOT_MAX_RESULT_BYTES}-byte limit.`,
      );
    }
    if (bytes > lease.remainingEgressBytes) {
      throw new BrokerRpcError(
        "EGRESS_BUDGET_EXCEEDED",
        "The lease model-egress byte budget is exhausted.",
      );
    }
    lease.remainingEgressBytes -= bytes;
    return bytes;
  }

  private async auditCommandDenied(lease: Lease, command: string, error: unknown): Promise<void> {
    const code = error instanceof BrokerRpcError ? error.code : "BROWSER_COMMAND_FAILED";
    await this.audit.record({
      event: "browser.command",
      outcome: "denied",
      clientId: lease.clientId,
      taskId: lease.taskId,
      leaseId: lease.leaseId,
      origin: lease.origin,
      method: command,
      reasonCode: code,
    });
  }

  private requireOwnedLease(context: ConnectionContext, leaseId: string, active = true): Lease {
    const lease = this.leases.get(leaseId);
    if (lease === undefined || !this.belongsTo(context, lease)) {
      throw new BrokerRpcError("LEASE_NOT_FOUND", "Lease does not belong to this client and task.");
    }
    if (active && !this.isLeaseActive(lease)) {
      throw new BrokerRpcError(
        lease.revokeReason ?? (lease.revokedAt === undefined ? "LEASE_EXPIRED" : "USER_REVOKED"),
        "Lease is no longer active.",
      );
    }
    return lease;
  }

  private requireScope(lease: Lease, scope: ImplementedScope): void {
    if (!lease.scopes.includes(scope)) {
      throw new BrokerRpcError("SCOPE_REQUIRED", `Lease does not grant ${scope}.`);
    }
  }

  private belongsTo(context: ConnectionContext, value: { sessionId: string }): boolean {
    return value.sessionId === this.sessionId(context);
  }

  private sessionId(context: ConnectionContext): string {
    const sessionId = this.sessionIds.get(context);
    if (sessionId === undefined) {
      throw new BrokerRpcError("INVALID_SESSION", "Broker connection session is not registered.");
    }
    return sessionId;
  }

  private reserveAccessRequestRate(context: ConnectionContext): void {
    const now = this.now();
    let sessionWindow = this.accessRequestWindows.get(context);
    if (sessionWindow === undefined) {
      sessionWindow = { startedAt: now, count: 0 };
      this.accessRequestWindows.set(context, sessionWindow);
    } else {
      this.resetWindowIfNeeded(sessionWindow, now);
    }
    this.resetWindowIfNeeded(this.globalAccessRequestWindow, now);

    if (sessionWindow.count >= ACCESS_REQUESTS_PER_SESSION_WINDOW) {
      throw new BrokerRpcError(
        "ACCESS_REQUEST_RATE_LIMIT",
        `A connection may create at most ${ACCESS_REQUESTS_PER_SESSION_WINDOW} access requests per minute.`,
      );
    }
    if (this.globalAccessRequestWindow.count >= ACCESS_REQUESTS_GLOBAL_WINDOW) {
      throw new BrokerRpcError(
        "GLOBAL_ACCESS_REQUEST_RATE_LIMIT",
        `The broker may create at most ${ACCESS_REQUESTS_GLOBAL_WINDOW} access requests per minute.`,
      );
    }
    sessionWindow.count += 1;
    this.globalAccessRequestWindow.count += 1;
  }

  private resetWindowIfNeeded(window: FixedWindow, now: number): void {
    if (
      window.startedAt === 0 ||
      now < window.startedAt ||
      now - window.startedAt >= ACCESS_REQUEST_RATE_WINDOW_MS
    ) {
      window.startedAt = now;
      window.count = 0;
    }
  }

  private ensureAccessRequestCapacity(): void {
    if (this.accessRequests.size < ACCESS_REQUEST_RECORD_LIMIT) return;
    const terminal = [...this.accessRequests.values()]
      .filter((request) => request.status !== "pending")
      .sort(
        (left, right) =>
          (left.terminalAt ?? left.createdAt) - (right.terminalAt ?? right.createdAt),
      );
    for (const request of terminal) {
      this.accessRequests.delete(request.requestId);
      if (this.accessRequests.size < ACCESS_REQUEST_RECORD_LIMIT) return;
    }
    throw new BrokerRpcError(
      "ACCESS_RECORD_CAPACITY",
      "The broker access-request record capacity is exhausted.",
    );
  }

  private ensureLeaseCapacity(): void {
    if (this.leases.size < LEASE_RECORD_LIMIT) return;
    const terminal = [...this.leases.values()]
      .filter((lease) => lease.revokedAt !== undefined)
      .sort((left, right) => (left.revokedAt ?? 0) - (right.revokedAt ?? 0));
    for (const lease of terminal) {
      this.leases.delete(lease.leaseId);
      if (this.leases.size < LEASE_RECORD_LIMIT) return;
    }
    throw new BrokerRpcError(
      "LEASE_RECORD_CAPACITY",
      "The broker lease record capacity is exhausted.",
    );
  }

  private maintainState(): void {
    const now = this.now();
    this.expireRecords(now);
    if (now < this.nextMaintenanceAt) return;
    const cutoff = now - TERMINAL_RECORD_RETENTION_MS;
    for (const request of this.accessRequests.values()) {
      if (
        request.status !== "pending" &&
        request.terminalAt !== undefined &&
        request.terminalAt <= cutoff
      ) {
        this.accessRequests.delete(request.requestId);
      }
    }
    for (const lease of this.leases.values()) {
      if (lease.revokedAt !== undefined && lease.revokedAt <= cutoff) {
        this.leases.delete(lease.leaseId);
      }
    }
    this.nextMaintenanceAt = now + STATE_MAINTENANCE_INTERVAL_MS;
  }

  private isLeaseActive(lease: Lease): boolean {
    if (lease.revokedAt !== undefined) {
      return false;
    }
    const now = this.now();
    if (lease.expiresAt <= now || lease.lastUsedAt + LEASE_IDLE_TIMEOUT_MS <= now) {
      this.revokeLease(lease, "LEASE_EXPIRED");
      return false;
    }
    if (lease.policyLease.remainingUses <= 0) {
      if (lease.inFlight === 0) {
        this.revokeLease(lease, "USE_LIMIT_EXHAUSTED");
        return false;
      }
      return true;
    }
    return true;
  }

  private revokeLease(lease: Lease, reason: string): void {
    if (lease.revokedAt !== undefined) {
      return;
    }
    lease.revokedAt = this.now();
    lease.revokeReason = reason;
    lease.policyLease.state = reason === "LEASE_EXPIRED" ? "expired" : "revoked";
    if (lease.policyLease.state === "revoked") {
      lease.policyLease.revokedAt = lease.revokedAt;
      lease.policyLease.revocationReason = reason;
    }
    const request = this.accessRequests.get(lease.requestId);
    if (request !== undefined) {
      request.status = reason === "LEASE_EXPIRED" ? "expired" : "revoked";
      request.terminalAt = lease.revokedAt;
    }
    const browser = this.browsers.get(lease.browserInstanceId);
    browser?.context.peer.sendEvent("access.revoked", { leaseId: lease.leaseId, reason });
  }

  private expireRecords(now = this.now()): void {
    for (const request of this.accessRequests.values()) {
      if (request.status === "pending" && request.expiresAt <= now) {
        request.status = "expired";
        request.terminalAt = now;
      }
    }
    for (const lease of this.leases.values()) {
      this.isLeaseActive(lease);
    }
  }

  private publicRequest(request: AccessRequest): unknown {
    return {
      requestId: request.requestId,
      clientId: request.clientId,
      taskId: request.taskId,
      scopes: request.scopes,
      reason: request.reason,
      ...(request.declaredModelProvider === undefined
        ? {}
        : { declaredModelProvider: request.declaredModelProvider }),
      status: request.status,
      expiresAt: new Date(request.expiresAt).toISOString(),
      ...(request.leaseId === undefined ? {} : { leaseId: request.leaseId }),
    };
  }

  private publicLease(lease: Lease): unknown {
    return {
      leaseId: lease.leaseId,
      requestId: lease.requestId,
      tabId: lease.tabId,
      documentId: lease.documentId,
      origin: lease.origin,
      url: redactUrl(lease.url),
      title: lease.title,
      scopes: lease.scopes,
      ...(lease.declaredModelProvider === undefined
        ? {}
        : { declaredModelProvider: lease.declaredModelProvider }),
      issuedAt: new Date(lease.issuedAt).toISOString(),
      expiresAt: new Date(lease.expiresAt).toISOString(),
      active: this.isLeaseActive(lease),
      remainingUses: lease.policyLease.remainingUses,
      remainingEgressBytes: lease.remainingEgressBytes,
      inFlight: lease.inFlight,
      ...(lease.revokeReason === undefined ? {} : { revokeReason: lease.revokeReason }),
    };
  }

  private authorizeCommand(lease: Lease, command: string, args: Record<string, unknown>): void {
    const action = actionForCommand(command, args);
    if (action === undefined) {
      if (command === "highlight") {
        this.requireScope(lease, "page.highlight");
        return;
      }
      throw new BrokerRpcError("UNKNOWN_ACTION", `Unsupported browser action: ${command}`);
    }
    const decision = evaluatePolicy({
      phase: "prepare",
      action,
      capability: lease.capability,
      lease: lease.policyLease,
      context: {
        now: this.now(),
        clientId: lease.clientId,
        taskId: lease.taskId,
        browserProfileInstance: lease.browserInstanceId,
        tabId: String(lease.tabId),
        documentId: lease.documentId,
        topLevelOrigin: lease.origin,
        audience: lease.clientId,
        policyVersion: "v0.1",
        capabilitySignatureVerified: this.capabilityIssuer.verify(lease.capability),
        enterpriseAllowed: true,
        rateLimitAllowed: lease.policyLease.remainingUses > 0,
      },
    });
    if (decision.outcome !== "ALLOW") {
      throw new BrokerRpcError(decision.errorCode ?? "POLICY_DENIED", decision.reason);
    }
  }
}

function redactUrl(value: string): string {
  const url = new URL(value);
  url.search = "";
  url.hash = "";
  return url.toString();
}

function actionForCommand(command: string, args: Record<string, unknown>): Action | undefined {
  switch (command) {
    case "snapshot":
      return {
        kind: "page.a11y.read",
        maxNodes: z.number().int().positive().max(500).parse(args.maxNodes),
      };
    case "scroll":
      return {
        kind: "page.scroll",
        deltaX: 0,
        deltaY: z.number().int().min(-2_000).max(2_000).parse(args.deltaY),
      };
    case "navigate":
      return { kind: "page.navigate", url: z.string().url().parse(args.url), target: "same-tab" };
    default:
      return undefined;
  }
}
