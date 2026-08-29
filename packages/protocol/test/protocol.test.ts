import { describe, expect, it } from "vitest";

import {
  AccessRequestSchema,
  ActionSchema,
  BrokerRequestSchema,
  CapabilitySchema,
  LeaseSchema,
  PROTOCOL_VERSION,
  ScopeSchema,
} from "../src/index.js";

const now = 1_800_000_000_000;

function capability() {
  return {
    version: PROTOCOL_VERSION,
    capabilityId: "cap-1",
    issuer: "broker-1",
    clientId: "agent-1",
    taskId: "task-1",
    browserProfileInstance: "profile-1",
    tabId: "tab-1",
    documentId: "doc-1",
    topLevelOrigin: "https://example.com",
    scopes: [{ kind: "page.a11y.read" }],
    dataClasses: ["visible"],
    egressDestinations: [],
    issuedAt: now,
    expiresAt: now + 60_000,
    idleTimeoutMs: 30_000,
    useLimit: 10,
    nonce: "nonce-1",
    audience: "broker-1",
    policyVersion: "policy-1",
    nonDelegable: true,
    signature: "signed-capability-1",
  } as const;
}

describe("protocol schemas", () => {
  it("accepts a tightly scoped capability and rejects excessive TTL", () => {
    expect(CapabilitySchema.safeParse(capability()).success).toBe(true);
    expect(CapabilitySchema.safeParse({ ...capability(), expiresAt: now + 600_001 }).success).toBe(
      false,
    );
  });

  it("rejects unknown capability fields and wildcard identifiers", () => {
    expect(CapabilitySchema.safeParse({ ...capability(), debug: true }).success).toBe(false);
    expect(CapabilitySchema.safeParse({ ...capability(), clientId: "*" }).success).toBe(false);
    expect(
      CapabilitySchema.safeParse({
        ...capability(),
        scopes: [{ kind: "page.a11y.read" }, { kind: "page.a11y.read" }],
      }).success,
    ).toBe(false);
  });

  it("only accepts canonical secure origins or loopback HTTP", () => {
    const base = capability();
    expect(
      CapabilitySchema.safeParse({ ...base, topLevelOrigin: "https://example.com/" }).success,
    ).toBe(false);
    expect(
      CapabilitySchema.safeParse({ ...base, topLevelOrigin: "http://example.com" }).success,
    ).toBe(false);
    expect(
      CapabilitySchema.safeParse({ ...base, topLevelOrigin: "http://localhost:3000" }).success,
    ).toBe(true);
  });

  it("does not expose cookie, debugger, or all-URLs scopes", () => {
    for (const kind of ["cookies", "debugger", "<all_urls>", "browser.cookie.read"]) {
      expect(ScopeSchema.safeParse({ kind }).success).toBe(false);
    }
  });

  it("rejects password fields and arbitrary execution actions", () => {
    expect(
      ActionSchema.safeParse({
        kind: "page.form.draft",
        fields: [
          {
            target: {
              referenceId: "ref-1",
              tabId: "tab-1",
              documentId: "doc-1",
              topLevelOrigin: "https://example.com",
              domEpoch: 1,
              role: "textbox",
              accessibleName: "Password",
              issuedAt: now,
              expiresAt: now + 10_000,
            },
            fieldName: "password",
            fieldType: "password",
            value: "hunter2",
            dataClass: "authentication",
          },
        ],
      }).success,
    ).toBe(false);

    for (const kind of ["browser.cookie.read", "browser.cdp.command", "browser.script.execute"]) {
      expect(ActionSchema.safeParse({ kind }).success).toBe(false);
    }
  });

  it("requires revoked leases to carry revocation metadata", () => {
    const lease = {
      version: PROTOCOL_VERSION,
      leaseId: "lease-1",
      capabilityId: "cap-1",
      clientId: "agent-1",
      taskId: "task-1",
      browserProfileInstance: "profile-1",
      tabId: "tab-1",
      documentId: "doc-1",
      topLevelOrigin: "https://example.com",
      state: "revoked",
      issuedAt: now,
      expiresAt: now + 60_000,
      lastUsedAt: now,
      idleTimeoutMs: 30_000,
      remainingUses: 1,
    };
    expect(LeaseSchema.safeParse(lease).success).toBe(false);
    expect(LeaseSchema.safeParse({ ...lease, revokedAt: now + 1 }).success).toBe(true);
  });

  it("validates explicit user-gesture access requests", () => {
    const access = {
      version: PROTOCOL_VERSION,
      requestId: "request-1",
      clientId: "agent-1",
      taskId: "task-1",
      browserProfileInstance: "profile-1",
      tabId: "tab-1",
      documentId: "doc-1",
      topLevelOrigin: "https://example.com",
      requestedScopes: [{ kind: "page.a11y.read" }],
      requestedDataClasses: ["visible"],
      requestedEgressDestinations: [],
      requestedTtlMs: 60_000,
      userGestureId: "gesture-1",
      userGestureAt: now,
    };
    expect(AccessRequestSchema.safeParse(access).success).toBe(true);
    expect(AccessRequestSchema.safeParse({ ...access, requestedTtlMs: 600_001 }).success).toBe(
      false,
    );
  });

  it("keeps wire requests strict", () => {
    expect(
      BrokerRequestSchema.safeParse({
        version: PROTOCOL_VERSION,
        requestId: "request-1",
        type: "broker.status.read",
        enumerateTabs: true,
      }).success,
    ).toBe(false);
  });
});
