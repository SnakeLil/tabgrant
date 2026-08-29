import { describe, expect, it, vi } from "vitest";
import type { AuthHello } from "../src/auth.js";
import type { AuditLogger, AuditRecord } from "../src/audit.js";
import { BrokerState } from "../src/broker-state.js";
import { CapabilityIssuer } from "../src/capability.js";
import {
  ACCESS_PENDING_GLOBAL_LIMIT,
  ACCESS_PENDING_PER_SESSION_LIMIT,
  ACCESS_REQUEST_RATE_WINDOW_MS,
  ACCESS_REQUEST_RECORD_LIMIT,
  ACCESS_REQUESTS_GLOBAL_WINDOW,
  ACCESS_REQUESTS_PER_SESSION_WINDOW,
  LEASE_COMMANDS_PER_WINDOW,
  LEASE_COMMAND_WINDOW_MS,
  LEASE_EGRESS_BUDGET_BYTES,
  LEASE_MAX_IN_FLIGHT,
  LEASE_RECORD_LIMIT,
  LEASE_USE_LIMIT,
  SNAPSHOT_MAX_RESULT_BYTES,
  STATE_MAINTENANCE_INTERVAL_MS,
  TERMINAL_RECORD_RETENTION_MS,
  type ImplementedScope,
} from "../src/constants.js";
import type { RpcPeer } from "../src/wire.js";

interface PublicLease {
  readonly leaseId: string;
  readonly remainingUses: number;
  readonly remainingEgressBytes: number;
  readonly inFlight: number;
  readonly active: boolean;
}

interface Fixture {
  readonly state: BrokerState;
  readonly agent: ReturnType<BrokerState["createContext"]>;
  readonly lease: PublicLease;
  readonly auditRecords: AuditRecord[];
  advance(milliseconds: number): void;
}

type BrokerContext = ReturnType<BrokerState["createContext"]>;

interface AccessHarness {
  readonly state: BrokerState;
  readonly browser: BrokerContext;
  readonly auditRecords: AuditRecord[];
  newAgent(suffix: string): BrokerContext;
  request(agent: BrokerContext): Promise<{ requestId: string }>;
  deny(requestId: string): Promise<void>;
  grant(agent: BrokerContext, ordinal?: number): Promise<PublicLease>;
  grantRequest(requestId: string, ordinal?: number): Promise<PublicLease>;
  advance(milliseconds: number): void;
}

describe("BrokerState lease resource limits", () => {
  it("atomically caps each lease at two in-flight commands", async () => {
    const resolvers: Array<(value: unknown) => void> = [];
    const fixture = await createFixture(
      ["page.scroll"],
      () => new Promise((resolve) => resolvers.push(resolve)),
    );

    const first = fixture.state.handle(fixture.agent, "browser.scroll", {
      leaseId: fixture.lease.leaseId,
      deltaY: 100,
    });
    const second = fixture.state.handle(fixture.agent, "browser.scroll", {
      leaseId: fixture.lease.leaseId,
      deltaY: 200,
    });
    expect(resolvers).toHaveLength(LEASE_MAX_IN_FLIGHT);

    await expect(
      fixture.state.handle(fixture.agent, "browser.scroll", {
        leaseId: fixture.lease.leaseId,
        deltaY: 300,
      }),
    ).rejects.toMatchObject({ code: "LEASE_CONCURRENCY_LIMIT" });

    for (const resolve of resolvers) resolve({ ok: true });
    await expect(Promise.all([first, second])).resolves.toEqual([{ ok: true }, { ok: true }]);

    const lease = await currentLease(fixture);
    expect(lease).toMatchObject({ inFlight: 0, remainingUses: LEASE_USE_LIMIT - 2 });
    expect(fixture.auditRecords).toContainEqual(
      expect.objectContaining({ outcome: "denied", reasonCode: "LEASE_CONCURRENCY_LIMIT" }),
    );
  });

  it("does not return an in-flight result after revocation", async () => {
    let resolveCommand: ((value: unknown) => void) | undefined;
    const fixture = await createFixture(
      ["page.scroll"],
      () => new Promise((resolve) => (resolveCommand = resolve)),
    );
    const command = fixture.state.handle(fixture.agent, "browser.scroll", {
      leaseId: fixture.lease.leaseId,
      deltaY: 100,
    });

    await fixture.state.handle(fixture.agent, "access.revoke", {
      leaseId: fixture.lease.leaseId,
    });
    resolveCommand?.({ private: "must not escape" });

    await expect(command).rejects.toMatchObject({ code: "AGENT_REVOKED" });
    expect(fixture.auditRecords).toContainEqual(
      expect.objectContaining({ outcome: "denied", reasonCode: "AGENT_REVOKED" }),
    );
  });

  it("enforces a 30-command fixed minute window without consuming rejected attempts", async () => {
    const fixture = await createFixture(["page.scroll"], () => Promise.resolve({ ok: true }));

    for (let index = 0; index < LEASE_COMMANDS_PER_WINDOW; index += 1) {
      await fixture.state.handle(fixture.agent, "browser.scroll", {
        leaseId: fixture.lease.leaseId,
        deltaY: 1,
      });
    }
    await expect(
      fixture.state.handle(fixture.agent, "browser.scroll", {
        leaseId: fixture.lease.leaseId,
        deltaY: 1,
      }),
    ).rejects.toMatchObject({ code: "LEASE_RATE_LIMIT" });
    expect((await currentLease(fixture)).remainingUses).toBe(
      LEASE_USE_LIMIT - LEASE_COMMANDS_PER_WINDOW,
    );

    fixture.advance(LEASE_COMMAND_WINDOW_MS + 1);
    await expect(
      fixture.state.handle(fixture.agent, "browser.scroll", {
        leaseId: fixture.lease.leaseId,
        deltaY: 1,
      }),
    ).resolves.toEqual({ ok: true });
  });

  it("permits exactly 250 admitted commands across rate windows", async () => {
    const fixture = await createFixture(["page.scroll"], () => Promise.resolve({ ok: true }));

    for (let index = 0; index < LEASE_USE_LIMIT; index += 1) {
      if (index > 0 && index % LEASE_COMMANDS_PER_WINDOW === 0) {
        fixture.advance(LEASE_COMMAND_WINDOW_MS + 1);
      }
      await fixture.state.handle(fixture.agent, "browser.scroll", {
        leaseId: fixture.lease.leaseId,
        deltaY: 1,
      });
    }

    await expect(
      fixture.state.handle(fixture.agent, "browser.scroll", {
        leaseId: fixture.lease.leaseId,
        deltaY: 1,
      }),
    ).rejects.toMatchObject({ code: "USE_LIMIT_EXHAUSTED" });
    expect(await currentLease(fixture)).toMatchObject({
      active: false,
      remainingUses: 0,
      inFlight: 0,
    });
  });

  it("charges only successfully returned snapshot UTF-8 JSON bytes", async () => {
    let result: unknown = { data: "🙂".repeat(64_000) };
    expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBeGreaterThan(
      SNAPSHOT_MAX_RESULT_BYTES,
    );
    const fixture = await createFixture(["page.a11y.read", "data.egress.model"], () =>
      Promise.resolve(result),
    );

    await expect(
      fixture.state.handle(fixture.agent, "browser.snapshot", {
        leaseId: fixture.lease.leaseId,
        maxNodes: 200,
      }),
    ).rejects.toMatchObject({ code: "SNAPSHOT_TOO_LARGE" });
    expect((await currentLease(fixture)).remainingEgressBytes).toBe(LEASE_EGRESS_BUDGET_BYTES);

    result = { data: "x".repeat(249_989) };
    expect(Buffer.byteLength(JSON.stringify(result), "utf8")).toBe(250_000);
    for (let index = 0; index < 4; index += 1) {
      await expect(
        fixture.state.handle(fixture.agent, "browser.snapshot", {
          leaseId: fixture.lease.leaseId,
          maxNodes: 200,
        }),
      ).resolves.toBe(result);
    }
    expect((await currentLease(fixture)).remainingEgressBytes).toBe(0);

    result = { data: "one more byte" };
    await expect(
      fixture.state.handle(fixture.agent, "browser.snapshot", {
        leaseId: fixture.lease.leaseId,
        maxNodes: 200,
      }),
    ).rejects.toMatchObject({ code: "EGRESS_BUDGET_EXCEEDED" });
    expect((await currentLease(fixture)).remainingEgressBytes).toBe(0);
    expect(fixture.auditRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ outcome: "denied", reasonCode: "SNAPSHOT_TOO_LARGE" }),
        expect.objectContaining({ outcome: "denied", reasonCode: "EGRESS_BUDGET_EXCEEDED" }),
      ]),
    );
  });

  it("atomically settles concurrent snapshot egress without overspending", async () => {
    let result: unknown = { data: "x".repeat(249_989) };
    let block = false;
    const resolvers: Array<(value: unknown) => void> = [];
    const fixture = await createFixture(["page.a11y.read", "data.egress.model"], () =>
      block ? new Promise((resolve) => resolvers.push(resolve)) : Promise.resolve(result),
    );

    for (const bytes of [250_000, 250_000, 200_000]) {
      result = { data: "x".repeat(bytes - 11) };
      await fixture.state.handle(fixture.agent, "browser.snapshot", {
        leaseId: fixture.lease.leaseId,
        maxNodes: 200,
      });
    }
    expect((await currentLease(fixture)).remainingEgressBytes).toBe(300_000);

    result = { data: "x".repeat(199_989) };
    block = true;
    const first = fixture.state.handle(fixture.agent, "browser.snapshot", {
      leaseId: fixture.lease.leaseId,
      maxNodes: 200,
    });
    const second = fixture.state.handle(fixture.agent, "browser.snapshot", {
      leaseId: fixture.lease.leaseId,
      maxNodes: 200,
    });
    expect(resolvers).toHaveLength(2);
    for (const resolve of resolvers) resolve(result);

    const settled = await Promise.allSettled([first, second]);
    expect(settled.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    const rejected = settled.find((item) => item.status === "rejected");
    const rejectionReason: unknown = rejected?.status === "rejected" ? rejected.reason : undefined;
    expect(rejected?.status).toBe("rejected");
    expect(rejectionReason).toMatchObject({ code: "EGRESS_BUDGET_EXCEEDED" });
    expect((await currentLease(fixture)).remainingEgressBytes).toBe(100_000);
  });
});

describe("BrokerState access-request memory and DoS limits", () => {
  it("caps pending requests per session without auditing each rejection", async () => {
    const harness = await createAccessHarness();
    const agent = harness.newAgent("one");
    for (let index = 0; index < ACCESS_PENDING_PER_SESSION_LIMIT; index += 1) {
      await harness.request(agent);
    }
    const auditCount = harness.auditRecords.length;

    await expect(harness.request(agent)).rejects.toMatchObject({
      code: "SESSION_PENDING_LIMIT",
    });
    expect(harness.auditRecords).toHaveLength(auditCount);
  });

  it("caps global pending requests and never exposes more than 100 to the extension", async () => {
    const harness = await createAccessHarness();
    for (let index = 0; index < ACCESS_PENDING_GLOBAL_LIMIT; index += 1) {
      await harness.request(harness.newAgent(`pending-${index}`));
    }
    const pending = (await harness.state.handle(harness.browser, "access.pending.list", {})) as {
      requests: unknown[];
    };
    expect(pending.requests).toHaveLength(ACCESS_PENDING_GLOBAL_LIMIT);
    const auditCount = harness.auditRecords.length;

    await expect(harness.request(harness.newAgent("overflow"))).rejects.toMatchObject({
      code: "GLOBAL_PENDING_LIMIT",
    });
    expect(harness.auditRecords).toHaveLength(auditCount);
    expect(
      (
        (await harness.state.handle(harness.browser, "access.pending.list", {})) as {
          requests: unknown[];
        }
      ).requests,
    ).toHaveLength(100);
  });

  it("enforces per-session and global fixed request windows without rejection fsyncs", async () => {
    const perSession = await createAccessHarness();
    const oneAgent = perSession.newAgent("rate-one");
    for (let index = 0; index < ACCESS_REQUESTS_PER_SESSION_WINDOW; index += 1) {
      const request = await perSession.request(oneAgent);
      await perSession.deny(request.requestId);
    }
    let auditCount = perSession.auditRecords.length;
    await expect(perSession.request(oneAgent)).rejects.toMatchObject({
      code: "ACCESS_REQUEST_RATE_LIMIT",
    });
    expect(perSession.auditRecords).toHaveLength(auditCount);

    perSession.advance(ACCESS_REQUEST_RATE_WINDOW_MS + 1);
    await expect(perSession.request(oneAgent)).resolves.toHaveProperty("requestId");

    const global = await createAccessHarness();
    const agents = Array.from({ length: 6 }, (_, index) => global.newAgent(`rate-${index}`));
    for (let index = 0; index < ACCESS_REQUESTS_GLOBAL_WINDOW; index += 1) {
      const agent = agents[index % agents.length];
      if (!agent) throw new Error("Missing rate-limit test agent.");
      const request = await global.request(agent);
      await global.deny(request.requestId);
    }
    auditCount = global.auditRecords.length;
    await expect(global.request(global.newAgent("global-overflow"))).rejects.toMatchObject({
      code: "GLOBAL_ACCESS_REQUEST_RATE_LIMIT",
    });
    expect(global.auditRecords).toHaveLength(auditCount);
  });

  it("evicts retained terminal records and keeps accessRequests at its hard capacity", async () => {
    const retention = await createAccessHarness();
    const retentionAgent = retention.newAgent("retention");
    const oldRequest = await retention.request(retentionAgent);
    await retention.deny(oldRequest.requestId);
    expect(await accessStatus(retention, retentionAgent)).toMatchObject({
      requests: [expect.objectContaining({ requestId: oldRequest.requestId, status: "denied" })],
    });

    retention.advance(TERMINAL_RECORD_RETENTION_MS + STATE_MAINTENANCE_INTERVAL_MS + 1);
    await retention.state.handle(retentionAgent, "broker.status", {});
    expect(await accessStatus(retention, retentionAgent)).toMatchObject({ requests: [] });

    const capacity = await createAccessHarness();
    const agents = Array.from({ length: 6 }, (_, index) => capacity.newAgent(`capacity-${index}`));
    for (let index = 0; index < ACCESS_REQUEST_RECORD_LIMIT + 5; index += 1) {
      if (index > 0 && index % ACCESS_REQUESTS_GLOBAL_WINDOW === 0) {
        capacity.advance(ACCESS_REQUEST_RATE_WINDOW_MS + 1);
      }
      const agent = agents[index % agents.length];
      if (!agent) throw new Error("Missing capacity test agent.");
      const request = await capacity.request(agent);
      await capacity.deny(request.requestId);
      expect(accessRecordCount(capacity.state)).toBeLessThanOrEqual(ACCESS_REQUEST_RECORD_LIMIT);
    }
    expect(accessRecordCount(capacity.state)).toBe(ACCESS_REQUEST_RECORD_LIMIT);
  });

  it("evicts terminal leases by retention and fails closed when all hard-cap leases are active", async () => {
    const retention = await createAccessHarness();
    const retentionAgent = retention.newAgent("lease-retention");
    const oldLease = await retention.grant(retentionAgent);
    await retention.state.handle(retentionAgent, "access.revoke", { leaseId: oldLease.leaseId });
    expect((await accessStatus(retention, retentionAgent)).leases).toHaveLength(1);

    retention.advance(TERMINAL_RECORD_RETENTION_MS + STATE_MAINTENANCE_INTERVAL_MS + 1);
    await retention.state.handle(retentionAgent, "broker.status", {});
    expect((await accessStatus(retention, retentionAgent)).leases).toHaveLength(0);

    const capacity = await createAccessHarness();
    const agents = Array.from({ length: 6 }, (_, index) => capacity.newAgent(`lease-${index}`));
    for (let index = 0; index < LEASE_RECORD_LIMIT; index += 1) {
      if (index > 0 && index % ACCESS_REQUESTS_GLOBAL_WINDOW === 0) {
        capacity.advance(ACCESS_REQUEST_RATE_WINDOW_MS + 1);
      }
      const agent = agents[index % agents.length];
      if (!agent) throw new Error("Missing lease-capacity test agent.");
      await capacity.grant(agent, index);
    }
    expect(leaseRecordCount(capacity.state)).toBe(LEASE_RECORD_LIMIT);

    const overflowAgent = agents[0];
    if (!overflowAgent) throw new Error("Missing overflow test agent.");
    const overflowRequest = await capacity.request(overflowAgent);
    const auditCount = capacity.auditRecords.length;
    await expect(
      capacity.grantRequest(overflowRequest.requestId, LEASE_RECORD_LIMIT + 1),
    ).rejects.toMatchObject({
      code: "LEASE_RECORD_CAPACITY",
    });
    expect(leaseRecordCount(capacity.state)).toBe(LEASE_RECORD_LIMIT);
    expect(capacity.auditRecords).toHaveLength(auditCount);
  });
});

async function createAccessHarness(): Promise<AccessHarness> {
  let now = 1_800_000_000_000;
  const auditRecords: AuditRecord[] = [];
  const audit = {
    record: vi.fn((record: AuditRecord) => {
      auditRecords.push(record);
      return Promise.resolve();
    }),
  } as unknown as AuditLogger;
  const state = new BrokerState(audit, new CapabilityIssuer(Buffer.alloc(32, 9)), () => now);
  const browserPeer = {
    request: vi.fn(() => Promise.resolve({ ok: true })),
    sendEvent: vi.fn(),
  } as unknown as RpcPeer;
  const browser = state.createContext(
    auth("browser", "tabgrant-extension", "browser"),
    browserPeer,
  );
  const browserInstanceId = crypto.randomUUID();
  await state.handle(browser, "browser.register", {
    browserInstanceId,
    extensionId: "a".repeat(32),
    browserName: "Chromium",
    browserVersion: "140",
  });

  const harness: AccessHarness = {
    state,
    browser,
    auditRecords,
    newAgent(suffix) {
      const peer = { request: vi.fn(), sendEvent: vi.fn() } as unknown as RpcPeer;
      return state.createContext(auth("agent", "codex", `task-${suffix}`), peer);
    },
    async request(agent) {
      return (await state.handle(agent, "access.request", {
        scopes: ["tab.metadata.read"],
        reason: "Synthetic access limit test",
      })) as { requestId: string };
    },
    async deny(requestId) {
      await state.handle(browser, "access.deny", { requestId });
    },
    async grant(agent, ordinal = 0) {
      const request = await harness.request(agent);
      return harness.grantRequest(request.requestId, ordinal);
    },
    async grantRequest(requestId, ordinal = 0) {
      return (await state.handle(browser, "access.grant", {
        requestId,
        browserInstanceId,
        tabId: ordinal,
        documentId: `document-${ordinal}`,
        origin: "https://example.test",
        url: `https://example.test/dashboard/${ordinal}`,
        title: "Synthetic dashboard",
        scopes: ["tab.metadata.read"],
        ttlSeconds: 600,
      })) as PublicLease;
    },
    advance(milliseconds) {
      now += milliseconds;
    },
  };
  return harness;
}

async function accessStatus(
  harness: AccessHarness,
  agent: BrokerContext,
): Promise<{ requests: unknown[]; leases: PublicLease[] }> {
  return (await harness.state.handle(agent, "access.status", {})) as {
    requests: unknown[];
    leases: PublicLease[];
  };
}

function accessRecordCount(state: BrokerState): number {
  return (
    state as unknown as {
      accessRequests: Map<string, unknown>;
    }
  ).accessRequests.size;
}

function leaseRecordCount(state: BrokerState): number {
  return (
    state as unknown as {
      leases: Map<string, unknown>;
    }
  ).leases.size;
}

async function createFixture(
  scopes: ImplementedScope[],
  execute: (method: string, params: unknown) => Promise<unknown>,
): Promise<Fixture> {
  let now = 1_800_000_000_000;
  const auditRecords: AuditRecord[] = [];
  const audit = {
    record: vi.fn((record: AuditRecord) => {
      auditRecords.push(record);
      return Promise.resolve();
    }),
  } as unknown as AuditLogger;
  const state = new BrokerState(audit, new CapabilityIssuer(Buffer.alloc(32, 7)), () => now);
  const browserPeer = {
    request: vi.fn(execute),
    sendEvent: vi.fn(),
  } as unknown as RpcPeer;
  const agentPeer = { request: vi.fn(), sendEvent: vi.fn() } as unknown as RpcPeer;
  const browser = state.createContext(
    auth("browser", "tabgrant-extension", "browser"),
    browserPeer,
  );
  const agent = state.createContext(auth("agent", "codex", "task-1"), agentPeer);
  const browserInstanceId = crypto.randomUUID();

  await state.handle(browser, "browser.register", {
    browserInstanceId,
    extensionId: "a".repeat(32),
    browserName: "Chromium",
    browserVersion: "140",
  });
  const request = (await state.handle(agent, "access.request", {
    scopes,
    reason: "Synthetic resource-limit test",
    ...(scopes.includes("data.egress.model") ? { declaredModelProvider: "openai" } : {}),
  })) as { requestId: string };
  const lease = (await state.handle(browser, "access.grant", {
    requestId: request.requestId,
    browserInstanceId,
    tabId: 7,
    documentId: "document-1",
    origin: "https://example.test",
    url: "https://example.test/dashboard",
    title: "Synthetic dashboard",
    scopes,
    ttlSeconds: 600,
  })) as PublicLease;

  expect(lease).toMatchObject({
    remainingUses: LEASE_USE_LIMIT,
    remainingEgressBytes: scopes.includes("data.egress.model") ? LEASE_EGRESS_BUDGET_BYTES : 0,
    inFlight: 0,
  });
  expect(lease).not.toHaveProperty("sessionId");

  return {
    state,
    agent,
    lease,
    auditRecords,
    advance(milliseconds: number) {
      now += milliseconds;
    },
  };
}

async function currentLease(fixture: Fixture): Promise<PublicLease> {
  const status = (await fixture.state.handle(fixture.agent, "access.status", {})) as {
    leases: PublicLease[];
  };
  const lease = status.leases.find((item) => item.leaseId === fixture.lease.leaseId);
  if (!lease) throw new Error("Fixture lease is missing from its owner session.");
  return lease;
}

function auth(role: "agent" | "browser", clientId: string, taskId: string): AuthHello {
  return {
    role,
    clientId,
    taskId,
    instanceId: crypto.randomUUID(),
    nonce: "a".repeat(32),
    timestamp: Date.now(),
    proof: "b".repeat(64),
  };
}
