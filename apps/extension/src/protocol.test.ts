import { describe, expect, it } from "vitest";
import {
  createWireError,
  createWireRequest,
  parseBrowserAuthChallenge,
  parseBrowserExecute,
  parseBrowserPublicKeyJwk,
  parseGrantedLease,
  parsePendingAccessRequest,
  parsePendingList,
  parsePopupRequest,
  parseWireEnvelope,
} from "./protocol.js";
import { grantableOrigin, sameOriginNavigation } from "./security.js";

const requestId = "11111111-1111-4111-8111-111111111111";
const leaseId = "22222222-2222-4222-8222-222222222222";

describe("native messaging wire v1", () => {
  it("creates the exact request envelope", () => {
    expect(createWireRequest("browser.register", { browserName: "Chromium" }, requestId)).toEqual({
      v: 1,
      kind: "request",
      id: requestId,
      method: "browser.register",
      params: { browserName: "Chromium" },
    });
  });

  it("parses strict responses and events", () => {
    expect(
      parseWireEnvelope({
        v: 1,
        kind: "response",
        id: requestId,
        ok: true,
        result: { registered: true },
      }),
    ).toEqual({
      v: 1,
      kind: "response",
      id: requestId,
      ok: true,
      result: { registered: true },
    });
    expect(parseWireEnvelope({ v: 1, kind: "event", event: "broker.killed", payload: {} })).toEqual(
      {
        v: 1,
        kind: "event",
        event: "broker.killed",
        payload: {},
      },
    );
    expect(
      parseWireEnvelope({ v: 1, kind: "event", event: "broker.killed", payload: {}, extra: true }),
    ).toBeUndefined();
  });

  it("emits broker-compatible errors", () => {
    expect(createWireError(requestId, "UNKNOWN_METHOD", "Denied")).toEqual({
      v: 1,
      kind: "response",
      id: requestId,
      ok: false,
      error: { code: "UNKNOWN_METHOD", message: "Denied" },
    });
  });
});

describe("broker payload parsing", () => {
  const pending = {
    requestId,
    clientId: "codex",
    taskId: "task-1",
    scopes: ["tab.metadata.read", "page.a11y.read", "data.egress.model"],
    reason: "Inspect the authenticated dashboard",
    status: "pending",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    declaredModelProvider: "openai",
  };

  it("parses pending access objects and lists", () => {
    expect(parsePendingAccessRequest(pending)).toMatchObject({
      requestId,
      clientId: "codex",
      taskId: "task-1",
      status: "pending",
    });
    expect(parsePendingList({ requests: [pending] })).toHaveLength(1);
  });

  it("accepts only strict, live browser authentication challenges and P-256 public keys", () => {
    const now = Date.now();
    const publicKey = { kty: "EC", crv: "P-256", x: "A".repeat(43), y: "B".repeat(43) };
    expect(parseBrowserPublicKeyJwk(publicKey)).toEqual(publicKey);
    expect(parseBrowserPublicKeyJwk({ ...publicKey, d: "private" })).toBeUndefined();
    expect(parseBrowserAuthChallenge({ paired: false }, now)).toEqual({ paired: false });
    const challenge = {
      paired: true,
      challengeId: requestId,
      challenge: "C".repeat(43),
      expiresAt: now + 30_000,
    };
    expect(parseBrowserAuthChallenge(challenge, now)).toEqual(challenge);
    expect(parseBrowserAuthChallenge(challenge, now + 30_000)).toBeUndefined();
    expect(parseBrowserAuthChallenge({ ...challenge, signature: "injected" }, now)).toBeUndefined();
  });

  it("rejects unknown scopes and missing model egress identity", () => {
    expect(parsePendingAccessRequest({ ...pending, scopes: ["page.click"] })).toBeUndefined();
    const withoutProvider: Partial<typeof pending> = { ...pending };
    delete withoutProvider.declaredModelProvider;
    expect(parsePendingAccessRequest(withoutProvider)).toBeUndefined();
  });

  it("accepts the broker's budgeted lease shape and rejects invalid counters", () => {
    const granted = {
      leaseId,
      requestId,
      tabId: 7,
      documentId: "document-1",
      origin: "https://github.com",
      url: "https://github.com/",
      title: "GitHub",
      scopes: ["page.a11y.read", "data.egress.model"],
      declaredModelProvider: "openai",
      issuedAt: new Date(Date.now() - 1_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      active: true,
      remainingUses: 250,
      remainingEgressBytes: 1_000_000,
      inFlight: 0,
    };
    expect(parseGrantedLease(granted)).toMatchObject({ leaseId, requestId, tabId: 7 });
    expect(parseGrantedLease({ ...granted, remainingEgressBytes: -1 })).toBeUndefined();
    expect(parseGrantedLease({ ...granted, inFlight: 1.5 })).toBeUndefined();
  });
});

describe("popup pairing gesture", () => {
  it("accepts only the explicit parameter-free Pair action", () => {
    expect(parsePopupRequest({ type: "popup.pair" })).toEqual({ type: "popup.pair" });
    expect(parsePopupRequest({ type: "popup.pair", pairingCode: "injected" })).toBeUndefined();
  });
});

describe("browser.execute allowlist", () => {
  const lease = {
    leaseId,
    tabId: 7,
    documentId: "document-1",
    origin: "https://github.com",
    scopes: ["page.a11y.read", "data.egress.model"],
    expiresAt: Date.now() + 60_000,
  };

  it("accepts the four typed commands", () => {
    expect(
      parseBrowserExecute({ command: "snapshot", lease, args: { maxNodes: 200 } })?.command,
    ).toBe("snapshot");
    expect(
      parseBrowserExecute({
        command: "highlight",
        lease: { ...lease, scopes: ["page.highlight"] },
        args: { ref: "tg-1", epoch: 3 },
      })?.command,
    ).toBe("highlight");
    expect(
      parseBrowserExecute({
        command: "scroll",
        lease: { ...lease, scopes: ["page.scroll"] },
        args: { deltaY: 600 },
      })?.command,
    ).toBe("scroll");
    expect(
      parseBrowserExecute({
        command: "navigate",
        lease: { ...lease, scopes: ["page.navigate.same_origin"] },
        args: { url: "https://github.com/openai/codex" },
      })?.command,
    ).toBe("navigate");
  });

  it.each(["click", "type", "evaluate", "cookies.read", "storage.read", "debugger.attach"])(
    "fails closed for %s",
    (command) => expect(parseBrowserExecute({ command, lease, args: {} })).toBeUndefined(),
  );

  it("rejects malformed and extra command fields", () => {
    expect(
      parseBrowserExecute({ command: "snapshot", lease, args: { maxNodes: 501 } }),
    ).toBeUndefined();
    expect(
      parseBrowserExecute({ command: "highlight", lease, args: { ref: "tg-1", epoch: -1 } }),
    ).toBeUndefined();
    expect(
      parseBrowserExecute({ command: "scroll", lease, args: { deltaY: 1, value: "secret" } }),
    ).toBeUndefined();
  });
});

describe("safe origin confinement", () => {
  it("allows HTTPS and loopback HTTP only", () => {
    expect(grantableOrigin("https://github.com/openai/codex")).toBe("https://github.com");
    expect(grantableOrigin("http://127.0.0.1:4173/dashboard")).toBe("http://127.0.0.1:4173");
    expect(grantableOrigin("http://localhost:3000/")).toBe("http://localhost:3000");
    expect(grantableOrigin("http://example.com/")).toBeUndefined();
    expect(grantableOrigin("chrome://settings")).toBeUndefined();
    expect(grantableOrigin("https://chromewebstore.google.com/detail/example")).toBeUndefined();
  });

  it("resolves only same-origin safe navigation", () => {
    expect(sameOriginNavigation("https://github.com", "/openai/codex")).toBe(
      "https://github.com/openai/codex",
    );
    expect(sameOriginNavigation("https://github.com", "https://example.com/")).toBeUndefined();
    expect(sameOriginNavigation("https://github.com", "javascript:alert(1)")).toBeUndefined();
  });
});
