import { describe, expect, it } from "vitest";

import { PROTOCOL_VERSION, type Action } from "@tabgrant/protocol";

import {
  PolicyAuthorizationError,
  assertAuthorized,
  canonicalizeAction,
  evaluatePolicy,
  hashAction,
  type PolicyContext,
  type PolicyEvaluationRequest,
} from "../src/index.js";

const now = 1_800_000_000_000;
const digestA = "a".repeat(64);
const digestB = "b".repeat(64);

function elementReference(overrides: Record<string, unknown> = {}) {
  return {
    referenceId: "ref-1",
    tabId: "tab-1",
    documentId: "doc-1",
    topLevelOrigin: "https://example.com",
    domEpoch: 7,
    role: "button",
    accessibleName: "Submit",
    issuedAt: now - 1_000,
    expiresAt: now + 30_000,
    ...overrides,
  };
}

function capability(overrides: Record<string, unknown> = {}) {
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
    scopes: [
      { kind: "page.a11y.read" },
      { kind: "page.screenshot.read" },
      { kind: "page.scroll" },
      { kind: "page.highlight" },
      { kind: "page.click.reversible" },
      { kind: "page.form.draft" },
      { kind: "page.navigate.same_origin" },
      { kind: "action.prepare", actionTypes: ["page.form.submit", "content.publish"] },
    ],
    dataClasses: ["public", "visible", "private", "sensitive"],
    egressDestinations: [],
    issuedAt: now - 1_000,
    expiresAt: now + 300_000,
    idleTimeoutMs: 120_000,
    useLimit: 100,
    nonce: "nonce-1",
    audience: "broker-1",
    policyVersion: "policy-1",
    nonDelegable: true,
    signature: "signed-capability-1",
    ...overrides,
  };
}

function lease(overrides: Record<string, unknown> = {}) {
  return {
    version: PROTOCOL_VERSION,
    leaseId: "lease-1",
    capabilityId: "cap-1",
    clientId: "agent-1",
    taskId: "task-1",
    browserProfileInstance: "profile-1",
    tabId: "tab-1",
    documentId: "doc-1",
    topLevelOrigin: "https://example.com",
    state: "active",
    issuedAt: now - 1_000,
    expiresAt: now + 300_000,
    lastUsedAt: now - 500,
    idleTimeoutMs: 120_000,
    remainingUses: 99,
    ...overrides,
  };
}

function context(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    now,
    clientId: "agent-1",
    taskId: "task-1",
    browserProfileInstance: "profile-1",
    tabId: "tab-1",
    documentId: "doc-1",
    topLevelOrigin: "https://example.com",
    audience: "broker-1",
    policyVersion: "policy-1",
    currentDomEpoch: 7,
    capabilitySignatureVerified: true,
    enterpriseAllowed: true,
    rateLimitAllowed: true,
    ...overrides,
  };
}

function request(
  action: unknown,
  overrides: Partial<PolicyEvaluationRequest> = {},
): PolicyEvaluationRequest {
  return {
    phase: "prepare",
    action,
    capability: capability(),
    lease: lease(),
    context: context(),
    ...overrides,
  };
}

function r2Action(): Action {
  return {
    kind: "page.form.submit",
    target: elementReference(),
    fieldsDigest: digestA,
    account: "alice@example.com",
    destination: "Example support form",
    summary: "Submit a support request",
    reversible: true,
    idempotencyKey: "submit-1",
  };
}

function approval(action: Action, overrides: Record<string, unknown> = {}) {
  return {
    prepareId: "prepare-1",
    actionHash: hashAction(action),
    stateWitnessHash: digestB,
    clientId: "agent-1",
    taskId: "task-1",
    tabId: "tab-1",
    documentId: "doc-1",
    topLevelOrigin: "https://example.com",
    policyVersion: "policy-1",
    issuedAt: now - 500,
    expiresAt: now + 30_000,
    userPresence: { method: "biometric", verifiedAt: now - 400 },
    signature: "signed-approval-1",
    ...overrides,
  };
}

describe("canonical action hashing", () => {
  it("is stable across property order and NFC-equivalent text", () => {
    const first = {
      kind: "content.publish",
      destination: "https://example.com/posts",
      contentDigest: digestA,
      summary: "Café",
      idempotencyKey: "publish-1",
    };
    const second = {
      idempotencyKey: "publish-1",
      summary: "Cafe\u0301",
      contentDigest: digestA,
      destination: "https://example.com/posts",
      kind: "content.publish",
    };
    expect(canonicalizeAction(first)).toBe(canonicalizeAction(second));
    expect(hashAction(first)).toBe(hashAction(second));
  });

  it("normalizes URLs and changes the hash when semantic parameters change", () => {
    const first = { kind: "page.navigate", url: "https://EXAMPLE.com:443/a", target: "same-tab" };
    const equivalent = { kind: "page.navigate", url: "https://example.com/a", target: "same-tab" };
    const changed = { kind: "page.navigate", url: "https://example.com/b", target: "same-tab" };
    expect(hashAction(first)).toBe(hashAction(equivalent));
    expect(hashAction(first)).not.toBe(hashAction(changed));
  });
});

describe("fail-closed policy engine", () => {
  it("allows a scoped R0 observation", () => {
    const decision = evaluatePolicy(request({ kind: "page.a11y.read", maxNodes: 100 }));
    expect(decision).toMatchObject({ outcome: "ALLOW", risk: "R0" });
  });

  it.each([
    ["clientId", "agent-2"],
    ["taskId", "task-2"],
    ["tabId", "tab-2"],
    ["documentId", "doc-2"],
    ["topLevelOrigin", "https://attacker.example"],
  ] as const)("rejects cross-context %s reuse", (field, value) => {
    const decision = evaluatePolicy(
      request({ kind: "page.a11y.read", maxNodes: 100 }, { context: context({ [field]: value }) }),
    );
    expect(decision).toMatchObject({ outcome: "DENY", errorCode: "CAPABILITY_CONTEXT_MISMATCH" });
  });

  it("rejects expired capabilities and revoked or idle leases", () => {
    expect(
      evaluatePolicy(
        request(
          { kind: "page.a11y.read", maxNodes: 100 },
          { capability: capability({ expiresAt: now }) },
        ),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "CAPABILITY_EXPIRED" });

    expect(
      evaluatePolicy(
        request(
          { kind: "page.a11y.read", maxNodes: 100 },
          {
            lease: lease({ state: "revoked", revokedAt: now - 1, revocationReason: "user" }),
          },
        ),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "LEASE_REVOKED" });

    expect(
      evaluatePolicy(
        request(
          { kind: "page.a11y.read", maxNodes: 100 },
          {
            capability: capability({ issuedAt: now - 200_000 }),
            lease: lease({ issuedAt: now - 200_000, lastUsedAt: now - 120_000 }),
          },
        ),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "LEASE_EXPIRED" });
  });

  it("rejects leases that expand the signed capability budget", () => {
    expect(
      evaluatePolicy(
        request(
          { kind: "page.a11y.read", maxNodes: 100 },
          { lease: lease({ remainingUses: 101 }) },
        ),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "CAPABILITY_INVALID" });

    expect(
      evaluatePolicy(
        request(
          { kind: "page.a11y.read", maxNodes: 100 },
          { lease: lease({ expiresAt: now + 300_001 }) },
        ),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "CAPABILITY_INVALID" });
  });

  it("rejects stale element references", () => {
    const action = {
      kind: "page.click.reversible",
      target: elementReference({ domEpoch: 6 }),
      expectedEffect: "reversible-ui-only",
    };
    expect(evaluatePolicy(request(action))).toMatchObject({
      outcome: "DENY",
      errorCode: "STALE_ELEMENT_REFERENCE",
    });
  });

  it("rejects unknown actions and privileged browser authorities", () => {
    expect(evaluatePolicy(request({ kind: "page.do-anything", payload: "x" }))).toMatchObject({
      outcome: "DENY",
      errorCode: "UNKNOWN_ACTION",
    });

    const forbidden = [
      ["browser.cookie.read", "COOKIE_ACCESS_FORBIDDEN"],
      ["browser.secret.read", "SECRET_ACCESS_FORBIDDEN"],
      ["browser.password.read", "SECRET_ACCESS_FORBIDDEN"],
      ["browser.script.execute", "ARBITRARY_CODE_FORBIDDEN"],
      ["browser.javascript.eval", "ARBITRARY_CODE_FORBIDDEN"],
      ["browser.cdp.command", "CDP_ACCESS_FORBIDDEN"],
      ["browser.debugger.attach", "CDP_ACCESS_FORBIDDEN"],
    ];
    for (const [kind, errorCode] of forbidden) {
      expect(evaluatePolicy(request({ kind, payload: "steal" }))).toMatchObject({
        outcome: "DENY",
        risk: "R4",
        errorCode,
      });
    }
  });

  it("fails closed when signature, enterprise policy, or rate budget are not explicit", () => {
    for (const changed of [
      context({ capabilitySignatureVerified: false }),
      context({ enterpriseAllowed: undefined }),
      context({ rateLimitAllowed: undefined }),
    ]) {
      expect(
        evaluatePolicy(request({ kind: "page.a11y.read", maxNodes: 100 }, { context: changed }))
          .outcome,
      ).toBe("DENY");
    }
  });

  it("rejects cross-origin navigation without a specific grant", () => {
    expect(
      evaluatePolicy(
        request({
          kind: "page.navigate",
          url: "https://attacker.example/collect",
          target: "same-tab",
        }),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "CAPABILITY_SCOPE_DENIED" });
  });

  it("allows R2 prepare but requires a stored preparation and approval for commit", () => {
    const action = r2Action();
    expect(evaluatePolicy(request(action))).toMatchObject({ outcome: "ALLOW_PREPARE", risk: "R2" });
    expect(evaluatePolicy(request(action, { phase: "commit" }))).toMatchObject({
      outcome: "DENY",
      errorCode: "PREPARE_REQUIRED",
    });

    const actionHash = hashAction(action);
    const commitContext = context({
      approvalSignatureVerified: true,
      stateWitnessHash: digestB,
      prepared: { prepareId: "prepare-1", actionHash, stateWitnessHash: digestB },
    });
    expect(
      evaluatePolicy(
        request(action, {
          phase: "commit",
          approval: approval(action),
          context: commitContext,
        }),
      ),
    ).toMatchObject({ outcome: "ALLOW", risk: "R2" });
  });

  it("rejects changed state, action, and replayed R2 approvals", () => {
    const action = r2Action();
    const prepared = {
      prepareId: "prepare-1",
      actionHash: hashAction(action),
      stateWitnessHash: digestB,
    };

    expect(
      evaluatePolicy(
        request(action, {
          phase: "commit",
          approval: approval(action),
          context: context({
            approvalSignatureVerified: true,
            stateWitnessHash: digestA,
            prepared,
          }),
        }),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "STATE_CHANGED" });

    expect(
      evaluatePolicy(
        request(action, {
          phase: "commit",
          approval: approval(action, { consumedAt: now - 1 }),
          context: context({
            approvalSignatureVerified: true,
            stateWitnessHash: digestB,
            prepared,
          }),
        }),
      ),
    ).toMatchObject({ outcome: "DENY", errorCode: "APPROVAL_REPLAYED" });
  });

  it("permits R3 preview but never R3 commit in v0.1", () => {
    const action = {
      kind: "content.publish",
      destination: "public release",
      contentDigest: digestA,
      summary: "Publish a production release",
      idempotencyKey: "publish-1",
    };
    expect(evaluatePolicy(request(action))).toMatchObject({ outcome: "ALLOW_PREPARE", risk: "R3" });
    expect(evaluatePolicy(request(action, { phase: "commit" }))).toMatchObject({
      outcome: "DENY",
      risk: "R3",
      errorCode: "RISK_NOT_SUPPORTED",
    });
  });

  it("throws a typed error from assertAuthorized", () => {
    expect(() => assertAuthorized(request({ kind: "browser.cookie.read" }))).toThrow(
      PolicyAuthorizationError,
    );
  });
});
