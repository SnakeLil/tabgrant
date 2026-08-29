import { randomBytes, randomUUID, webcrypto } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  browserAuthPayload,
  browserPublicKeyFingerprint,
  type BrowserPublicKeyJwk,
  type PairingApprover,
} from "../src/auth.js";
import { BrokerDaemon } from "../src/daemon.js";
import { connectBroker, type BrokerClient } from "../src/client.js";
import type { RuntimePaths } from "../src/paths.js";
import { BrokerRpcError } from "../src/wire.js";

interface PublicRequest {
  readonly requestId: string;
}

interface PublicLease {
  readonly leaseId: string;
}

describe("broker end-to-end authority boundary", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
  });

  it("grants one document to one task, minimizes output, and rejects confused deputies", async () => {
    const { paths, daemon, directory } = await startTestDaemon();
    const clients: BrokerClient[] = [];
    cleanups.push(async () => {
      for (const client of clients) client.socket.destroy();
      await daemon.stop();
      await new Promise((resolve) => setTimeout(resolve, 20));
      await rm(directory, { recursive: true, force: true });
    });

    const browserInstanceId = crypto.randomUUID();
    const browser = await connectPairedBrowser(
      paths,
      "a".repeat(32),
      browserInstanceId,
      (method, params) => {
        expect(method).toBe("browser.execute");
        const command = (params as { command: string }).command;
        if (command === "snapshot") {
          return Promise.resolve({
            epoch: 3,
            nodes: [{ ref: "tg-1", role: "heading", name: "Private dashboard" }],
          });
        }
        return Promise.resolve({ ok: true });
      },
    );
    clients.push(browser);
    await browser.peer.request("browser.register", {
      browserInstanceId,
      extensionId: "a".repeat(32),
      browserName: "Chrome",
      browserVersion: "140.0.0.0",
    });

    const agent = await connectBroker(
      { clientId: "codex", taskId: "task-1", instanceId: crypto.randomUUID() },
      paths,
    );
    clients.push(agent);
    const request = (await agent.peer.request("access.request", {
      reason: "Inspect the authenticated QA dashboard",
      scopes: [
        "tab.metadata.read",
        "page.a11y.read",
        "page.scroll",
        "page.navigate.same_origin",
        "data.egress.model",
      ],
      declaredModelProvider: "openai",
    })) as PublicRequest;

    const lease = (await browser.peer.request("access.grant", {
      requestId: request.requestId,
      browserInstanceId,
      tabId: 7,
      documentId: "document-1",
      origin: "http://127.0.0.1:4173",
      url: "http://127.0.0.1:4173/dashboard?token=must-not-log#fragment",
      title: "QA dashboard",
      scopes: [
        "tab.metadata.read",
        "page.a11y.read",
        "page.scroll",
        "page.navigate.same_origin",
        "data.egress.model",
      ],
      ttlSeconds: 60,
    })) as PublicLease;

    await expect(
      agent.peer.request("browser.snapshot", { leaseId: lease.leaseId, maxNodes: 200 }),
    ).resolves.toEqual({
      epoch: 3,
      nodes: [{ ref: "tg-1", role: "heading", name: "Private dashboard" }],
    });

    const otherAgent = await connectBroker(
      { clientId: "codex", taskId: "task-2", instanceId: crypto.randomUUID() },
      paths,
    );
    clients.push(otherAgent);
    await expect(otherAgent.peer.request("browser.tabs.list", {})).resolves.toEqual({ tabs: [] });
    await expect(
      otherAgent.peer.request("browser.snapshot", { leaseId: lease.leaseId, maxNodes: 20 }),
    ).rejects.toMatchObject({
      code: "LEASE_NOT_FOUND",
    });

    const sameIdentityOtherSession = await connectBroker(
      { clientId: "codex", taskId: "task-1", instanceId: crypto.randomUUID() },
      paths,
    );
    clients.push(sameIdentityOtherSession);
    await expect(sameIdentityOtherSession.peer.request("access.status", {})).resolves.toEqual({
      requests: [],
      leases: [],
    });
    await expect(sameIdentityOtherSession.peer.request("browser.tabs.list", {})).resolves.toEqual({
      tabs: [],
    });
    await expect(
      sameIdentityOtherSession.peer.request("browser.snapshot", {
        leaseId: lease.leaseId,
        maxNodes: 20,
      }),
    ).rejects.toMatchObject({ code: "LEASE_NOT_FOUND" });
    await expect(
      sameIdentityOtherSession.peer.request("access.revoke", { leaseId: lease.leaseId }),
    ).rejects.toMatchObject({ code: "LEASE_NOT_FOUND" });
    await expect(
      agent.peer.request("browser.navigate", {
        leaseId: lease.leaseId,
        url: "https://attacker.example/",
      }),
    ).rejects.toMatchObject({ code: "ORIGIN_CHANGED" });

    await browser.peer.request("access.revoke", { leaseId: lease.leaseId, reason: "USER_REVOKED" });
    await expect(
      agent.peer.request("browser.snapshot", { leaseId: lease.leaseId, maxNodes: 20 }),
    ).rejects.toBeInstanceOf(BrokerRpcError);

    await new Promise((resolve) => setTimeout(resolve, 20));
    const audit = await readFile(paths.auditPath, "utf8");
    expect(audit).not.toContain("must-not-log");
    expect(audit).not.toContain("Private dashboard");
  });

  it("fails closed for unknown methods and scope escalation", async () => {
    const { paths, daemon, directory } = await startTestDaemon();
    const clients: BrokerClient[] = [];
    cleanups.push(async () => {
      for (const client of clients) client.socket.destroy();
      await daemon.stop();
      await new Promise((resolve) => setTimeout(resolve, 20));
      await rm(directory, { recursive: true, force: true });
    });
    const browserInstanceId = crypto.randomUUID();
    const browser = await connectPairedBrowser(paths, "b".repeat(32), browserInstanceId);
    const agent = await connectBroker(
      { clientId: "codex", taskId: "task-1", instanceId: crypto.randomUUID() },
      paths,
    );
    clients.push(browser, agent);
    await browser.peer.request("browser.register", {
      browserInstanceId,
      extensionId: "b".repeat(32),
      browserName: "Chrome",
      browserVersion: "140",
    });
    const request = (await agent.peer.request("access.request", {
      reason: "Read-only test",
      scopes: ["tab.metadata.read"],
    })) as PublicRequest;

    await expect(
      browser.peer.request("access.grant", {
        requestId: request.requestId,
        browserInstanceId,
        tabId: 1,
        documentId: "document-1",
        origin: "https://github.com",
        url: "https://github.com/",
        title: "GitHub",
        scopes: ["tab.metadata.read", "page.a11y.read"],
      }),
    ).rejects.toMatchObject({ code: "SCOPE_ESCALATION" });
    await expect(
      agent.peer.request("browser.execute_javascript", { source: "document.cookie" }),
    ).rejects.toMatchObject({
      code: "UNKNOWN_METHOD",
    });
  });

  it("keeps forged browser hellos as agents and consumes browser challenges once", async () => {
    let clock = Date.now();
    const { paths, daemon, directory } = await startTestDaemon(
      { approve: () => Promise.resolve(true) },
      () => clock,
    );
    const clients: BrokerClient[] = [];
    cleanups.push(async () => {
      for (const client of clients) client.socket.destroy();
      await daemon.stop();
      await rm(directory, { recursive: true, force: true });
    });

    const forged = await connectBroker({ clientId: "forged-browser", taskId: "forged" }, paths);
    clients.push(forged);
    await expect(forged.peer.request("broker.status", {})).resolves.toMatchObject({
      role: "agent",
    });
    await expect(
      forged.peer.request("browser.register", {
        browserInstanceId: randomUUID(),
        extensionId: "c".repeat(32),
        browserName: "Fake",
        browserVersion: "1",
      }),
    ).rejects.toMatchObject({ code: "UNKNOWN_METHOD" });
    await expect(forged.peer.request("broker.kill", {})).rejects.toMatchObject({
      code: "UNKNOWN_METHOD",
    });

    const keys = await browserKeyPair();
    const extensionId = "d".repeat(32);
    const browserInstanceId = randomUUID();
    const challenge = (await forged.peer.request("browser.auth.pair", {
      extensionId,
      browserInstanceId,
      publicKey: keys.publicKey,
      pairingCode: pairingCodeForTest(),
    })) as { paired: true; challengeId: string; challenge: string; expiresAt: number };
    const attackerKeys = await browserKeyPair();
    const wrongSignature = await signChallenge(
      challenge,
      extensionId,
      browserInstanceId,
      attackerKeys,
    );
    await expect(
      forged.peer.request("browser.auth.complete", {
        challengeId: challenge.challengeId,
        signature: wrongSignature,
      }),
    ).rejects.toMatchObject({ code: "BROWSER_AUTHENTICATION_FAILED" });
    const signature = await signChallenge(challenge, extensionId, browserInstanceId, keys);
    await expect(
      forged.peer.request("browser.auth.complete", {
        challengeId: challenge.challengeId,
        signature,
      }),
    ).rejects.toMatchObject({ code: "BROWSER_AUTHENTICATION_FAILED" });
    await expect(access(join(directory, "browser-pairing.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(
      forged.peer.request("browser.auth.start", {
        extensionId,
        browserInstanceId,
        publicKey: keys.publicKey,
      }),
    ).resolves.toEqual({ paired: false });

    clock += 30_001;
    const freshChallenge = (await forged.peer.request("browser.auth.pair", {
      extensionId,
      browserInstanceId,
      publicKey: keys.publicKey,
      pairingCode: pairingCodeForTest(),
    })) as { paired: true; challengeId: string; challenge: string; expiresAt: number };
    const freshSignature = await signChallenge(
      freshChallenge,
      extensionId,
      browserInstanceId,
      keys,
    );
    await expect(
      forged.peer.request("browser.auth.complete", {
        challengeId: freshChallenge.challengeId,
        signature: freshSignature,
      }),
    ).resolves.toMatchObject({ authenticated: true, role: "browser" });
    await expect(access(join(directory, "browser-pairing.json"))).resolves.toBeUndefined();
  });

  it("serializes browser auth transitions and preserves a challenge after an unknown id", async () => {
    let releaseLookup: ((paired: boolean) => void) | undefined;
    let signalLookupStarted: (() => void) | undefined;
    const lookupStarted = new Promise<void>((resolve) => {
      signalLookupStarted = resolve;
    });
    const pairingLookup: ConstructorParameters<typeof BrokerDaemon>[3] = () => {
      signalLookupStarted?.();
      return new Promise<boolean>((resolve) => {
        releaseLookup = resolve;
      });
    };
    const { paths, daemon, directory } = await startTestDaemon(
      { approve: () => Promise.resolve(true) },
      Date.now,
      pairingLookup,
    );
    const client = await connectBroker({ clientId: "browser-relay", taskId: "auth-race" }, paths);
    cleanups.push(async () => {
      client.socket.destroy();
      await daemon.stop();
      await rm(directory, { recursive: true, force: true });
    });
    const keys = await browserKeyPair();
    const extensionId = "p".repeat(32);
    const browserInstanceId = randomUUID();
    const identity = { extensionId, browserInstanceId, publicKey: keys.publicKey };
    const pairing = { ...identity, pairingCode: pairingCodeForTest() };

    const initialAuthentication = client.peer.request("browser.auth.start", identity);
    await lookupStarted;
    await expect(client.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
      code: "BROWSER_AUTHENTICATION_BUSY",
    });
    releaseLookup?.(false);
    await expect(initialAuthentication).resolves.toEqual({ paired: false });

    const challenge = (await client.peer.request("browser.auth.pair", pairing)) as {
      paired: true;
      challengeId: string;
      challenge: string;
      expiresAt: number;
    };
    await expect(client.peer.request("browser.auth.start", identity)).rejects.toMatchObject({
      code: "BROWSER_AUTHENTICATION_BUSY",
    });
    await expect(client.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
      code: "BROWSER_AUTHENTICATION_BUSY",
    });

    const signature = await signChallenge(challenge, extensionId, browserInstanceId, keys);
    await expect(
      client.peer.request("browser.auth.complete", {
        challengeId: randomUUID(),
        signature,
      }),
    ).rejects.toMatchObject({ code: "BROWSER_AUTHENTICATION_FAILED" });
    await expect(
      client.peer.request("browser.auth.complete", {
        challengeId: challenge.challengeId,
        signature,
      }),
    ).resolves.toMatchObject({ authenticated: true, role: "browser" });
  });

  it("cannot pair an attacker-selected key when local user presence denies it", async () => {
    let approvalRequest: Parameters<PairingApprover["approve"]>[0] | undefined;
    const denyingApprover: PairingApprover = {
      approve: (request) => {
        approvalRequest = request;
        return Promise.resolve(false);
      },
    };
    const { paths, daemon, directory } = await startTestDaemon(denyingApprover);
    const attacker = await connectBroker({ clientId: "attacker", taskId: "attacker" }, paths);
    cleanups.push(async () => {
      attacker.socket.destroy();
      await daemon.stop();
      await rm(directory, { recursive: true, force: true });
    });
    const keys = await browserKeyPair();
    const identity = {
      extensionId: "e".repeat(32),
      browserInstanceId: randomUUID(),
      publicKey: keys.publicKey,
    };
    const attackerCode = pairingCodeForTest();
    await expect(
      attacker.peer.request("browser.auth.pair", {
        ...identity,
        pairingCode: attackerCode,
      }),
    ).rejects.toMatchObject({ code: "BROWSER_PAIRING_DENIED" });
    expect(approvalRequest).toEqual({
      extensionId: identity.extensionId,
      browserInstanceId: identity.browserInstanceId,
      pairingCode: attackerCode,
      keyFingerprint: browserPublicKeyFingerprint(keys.publicKey),
    });
    await expect(attacker.peer.request("browser.auth.start", identity)).resolves.toEqual({
      paired: false,
    });
    await expect(
      attacker.peer.request("browser.auth.propose", {
        ...identity,
        codeHash: "0".repeat(64),
      }),
    ).rejects.toMatchObject({ code: "UNKNOWN_METHOD" });
    await expect(access(join(directory, "browser-pairing-proposals.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(await readFile(paths.auditPath, "utf8")).not.toContain(attackerCode);
  });

  it("bounds prompt occupancy globally even when an attacker opens fresh connections", async () => {
    let clock = 1_800_000_000_000;
    let releaseFirst: ((approved: boolean) => void) | undefined;
    let signalStarted: (() => void) | undefined;
    let firstPrompt = true;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const approver: PairingApprover = {
      approve: () => {
        if (firstPrompt) {
          firstPrompt = false;
          signalStarted?.();
          return new Promise<boolean>((resolve) => {
            releaseFirst = resolve;
          });
        }
        return Promise.resolve(false);
      },
    };
    const { paths, daemon, directory } = await startTestDaemon(approver, () => clock);
    const first = await connectBroker({ clientId: "first", taskId: "first" }, paths);
    const second = await connectBroker({ clientId: "second", taskId: "second" }, paths);
    const freshClients: BrokerClient[] = [];
    cleanups.push(async () => {
      first.socket.destroy();
      second.socket.destroy();
      for (const client of freshClients) client.socket.destroy();
      await daemon.stop();
      await rm(directory, { recursive: true, force: true });
    });
    const keys = await browserKeyPair();
    const pairing = {
      extensionId: "f".repeat(32),
      browserInstanceId: randomUUID(),
      publicKey: keys.publicKey,
      pairingCode: pairingCodeForTest(),
    };
    const firstAttempt = first.peer.request("browser.auth.pair", pairing);
    await started;
    await expect(second.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
      code: "BROWSER_PAIRING_BUSY",
    });
    releaseFirst?.(false);
    await expect(firstAttempt).rejects.toMatchObject({ code: "BROWSER_PAIRING_DENIED" });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      clock += 30_001;
      await expect(first.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
        code: "BROWSER_PAIRING_DENIED",
      });
    }
    clock += 30_001;
    await expect(first.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
      code: "BROWSER_PAIRING_RATE_LIMIT",
    });

    const bypass = await connectBroker({ clientId: "bypass", taskId: "fresh-connection" }, paths);
    freshClients.push(bypass);
    await expect(bypass.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
      code: "BROWSER_PAIRING_GLOBAL_RATE_LIMIT",
    });

    clock += 10 * 60_000;
    const afterWindow = await connectBroker(
      { clientId: "after-window", taskId: "fresh-connection" },
      paths,
    );
    freshClients.push(afterWindow);
    await expect(afterWindow.peer.request("browser.auth.pair", pairing)).rejects.toMatchObject({
      code: "BROWSER_PAIRING_DENIED",
    });
  });

  it("starts the signing challenge after a slow user approval completes", async () => {
    let clock = 1_800_000_000_000;
    const approver: PairingApprover = {
      approve: () => {
        clock += 55_000;
        return Promise.resolve(true);
      },
    };
    const { paths, daemon, directory } = await startTestDaemon(approver, () => clock);
    const client = await connectBroker({ clientId: "browser-relay", taskId: "pairing" }, paths);
    const second = await connectBroker({ clientId: "second-relay", taskId: "pairing" }, paths);
    cleanups.push(async () => {
      client.socket.destroy();
      second.socket.destroy();
      await daemon.stop();
      await rm(directory, { recursive: true, force: true });
    });
    const keys = await browserKeyPair();
    const challenge = (await client.peer.request("browser.auth.pair", {
      extensionId: "g".repeat(32),
      browserInstanceId: randomUUID(),
      publicKey: keys.publicKey,
      pairingCode: pairingCodeForTest(),
    })) as { paired: true; expiresAt: number };
    expect(challenge.expiresAt).toBe(clock + 30_000);
    await expect(
      second.peer.request("browser.auth.pair", {
        extensionId: "g".repeat(32),
        browserInstanceId: randomUUID(),
        publicKey: keys.publicKey,
        pairingCode: pairingCodeForTest(),
      }),
    ).rejects.toMatchObject({ code: "BROWSER_PAIRING_COOLDOWN" });
    await expect(access(join(directory, "browser-pairing.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("drains browser disconnect audit writes before daemon stop resolves", async () => {
    const { paths, daemon, directory } = await startTestDaemon();
    cleanups.push(async () => {
      await daemon.stop();
      await rm(directory, { recursive: true, force: true });
    });
    const browserInstanceId = randomUUID();
    const browser = await connectPairedBrowser(paths, "h".repeat(32), browserInstanceId);
    await browser.peer.request("browser.register", {
      browserInstanceId,
      extensionId: "h".repeat(32),
      browserName: "Chrome",
      browserVersion: "140",
    });

    await daemon.stop();

    expect(await readFile(paths.auditPath, "utf8")).toContain('"event":"browser.disconnected"');
  });
});

async function connectPairedBrowser(
  paths: RuntimePaths,
  extensionId: string,
  browserInstanceId: string,
  onRequest: (method: string, params: unknown) => Promise<unknown> = () =>
    Promise.reject(new Error("Unexpected browser request.")),
): Promise<BrokerClient> {
  const keys = await browserKeyPair();
  const client = await connectBroker(
    {
      clientId: "tabgrant-extension",
      taskId: "browser",
      instanceId: randomUUID(),
    },
    paths,
    onRequest,
  );
  const pairingCode = pairingCodeForTest();
  const challenge = (await client.peer.request("browser.auth.pair", {
    extensionId,
    browserInstanceId,
    publicKey: keys.publicKey,
    pairingCode,
  })) as { paired: true; challengeId: string; challenge: string; expiresAt: number };
  const signature = await signChallenge(challenge, extensionId, browserInstanceId, keys);
  await client.peer.request("browser.auth.complete", {
    challengeId: challenge.challengeId,
    signature,
  });
  return client;
}

async function browserKeyPair(): Promise<{
  publicKey: BrowserPublicKeyJwk;
  privateKey: CryptoKey;
}> {
  const pair = (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    publicKey: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! },
    privateKey: pair.privateKey,
  };
}

async function signChallenge(
  challenge: { challengeId: string; challenge: string; expiresAt: number },
  extensionId: string,
  browserInstanceId: string,
  keys: Awaited<ReturnType<typeof browserKeyPair>>,
): Promise<string> {
  const signature = await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keys.privateKey,
    new TextEncoder().encode(
      browserAuthPayload({
        ...challenge,
        extensionId,
        browserInstanceId,
        publicKey: keys.publicKey,
      }),
    ),
  );
  return Buffer.from(signature).toString("base64url");
}

function pairingCodeForTest(): string {
  const compact = randomBytes(20).toString("hex").toUpperCase();
  return compact.match(/.{1,4}/g)!.join("-");
}

async function startTestDaemon(
  pairingApprover: PairingApprover = { approve: () => Promise.resolve(true) },
  now: () => number = Date.now,
  browserPairingLookup?: ConstructorParameters<typeof BrokerDaemon>[3],
): Promise<{
  directory: string;
  paths: RuntimePaths;
  daemon: BrokerDaemon;
}> {
  const directory = await mkdtemp(join(tmpdir(), "tabgrant-test-"));
  const paths: RuntimePaths = {
    baseDirectory: directory,
    runtimeDirectory: join(directory, "run"),
    socketPath: join(directory, "run", "broker.sock"),
    secretPath: join(directory, "broker.secret"),
    authoritySecretPath: join(directory, "authority.secret"),
    auditPath: join(directory, "audit.jsonl"),
    killSwitchPath: join(directory, "disabled.json"),
  };
  const daemon = new BrokerDaemon(paths, pairingApprover, now, browserPairingLookup);
  await daemon.start();
  return { directory, paths, daemon };
}
