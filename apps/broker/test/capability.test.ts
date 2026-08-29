import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CapabilityIssuer } from "../src/capability.js";

describe("capability issuer", () => {
  it("binds a signed capability to client, task, tab, document, and origin", () => {
    const issuer = new CapabilityIssuer(randomBytes(32));
    const capability = issuer.issue({
      clientId: "codex",
      taskId: "task-1",
      browserInstanceId: "browser-1",
      tabId: 7,
      documentId: "document-1",
      origin: "https://github.com",
      scopes: ["page.a11y.read", "data.egress.model"],
      declaredModelProvider: "openai",
      issuedAt: 1_800_000_000_000,
      expiresAt: 1_800_000_600_000,
      useLimit: 10,
    });

    expect(issuer.verify(capability)).toBe(true);
    expect(issuer.verify({ ...capability, taskId: "task-2" })).toBe(false);
    expect(capability.scopes).toContainEqual({
      kind: "data.egress.model",
      providerId: "openai",
      dataClasses: ["visible", "private"],
      maxBytes: 1_000_000,
    });
  });

  it("rejects non-loopback cleartext origins", () => {
    const issuer = new CapabilityIssuer(randomBytes(32));
    expect(() =>
      issuer.issue({
        clientId: "codex",
        taskId: "task-1",
        browserInstanceId: "browser-1",
        tabId: 7,
        documentId: "document-1",
        origin: "http://example.com",
        scopes: ["page.a11y.read"],
        issuedAt: 1_800_000_000_000,
        expiresAt: 1_800_000_600_000,
        useLimit: 10,
      }),
    ).toThrow();
  });
});
