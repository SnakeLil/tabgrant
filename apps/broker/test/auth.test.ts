import { randomBytes, randomUUID, webcrypto } from "node:crypto";
import { chmod, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  browserAuthPayload,
  BrowserPairingRequestSchema,
  createAuthHello,
  createBrowserAuthChallenge,
  deriveBrokerSecret,
  isPairedBrowserKey,
  persistApprovedBrowserPairing,
  readBrokerSecret,
  verifyAuthHello,
  verifyBrowserAuthSignature,
  type BrowserPublicKeyJwk,
} from "../src/auth.js";

describe("local broker authentication", () => {
  const directories: string[] = [];

  afterEach(async () => {
    await Promise.allSettled(
      directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
    );
  });

  it("accepts a fresh bound proof and rejects replay", () => {
    const secret = randomBytes(32);
    const now = 1_800_000_000_000;
    const hello = createAuthHello(
      secret,
      { role: "agent", clientId: "codex", taskId: "task-1", instanceId: randomUUID() },
      now,
    );
    const nonces = new Set<string>();

    expect(verifyAuthHello(hello, secret, nonces, now)).toEqual(hello);
    expect(() => verifyAuthHello(hello, secret, nonces, now)).toThrow(/already used/i);
  });

  it("normalizes every shared-secret hello to agent authority", () => {
    const secret = randomBytes(32);
    const now = 1_800_000_000_000;
    const claimedBrowser = createAuthHello(
      secret,
      { role: "browser", clientId: "forged", taskId: "forged", instanceId: randomUUID() },
      now,
    );
    expect(verifyAuthHello(claimedBrowser, secret, new Set(), now).role).toBe("agent");
  });

  it("rejects identity tampering and stale timestamps", () => {
    const secret = randomBytes(32);
    const now = 1_800_000_000_000;
    const hello = createAuthHello(
      secret,
      { role: "agent", clientId: "codex", taskId: "task-1", instanceId: randomUUID() },
      now,
    );

    expect(() => verifyAuthHello({ ...hello, taskId: "task-2" }, secret, new Set(), now)).toThrow(
      /invalid/i,
    );
    expect(() => verifyAuthHello(hello, secret, new Set(), now + 31_000)).toThrow(/window/i);
  });

  it("domain-separates capability and audit keys", () => {
    const root = randomBytes(32);
    expect(deriveBrokerSecret(root, "capability")).not.toEqual(deriveBrokerSecret(root, "audit"));
  });

  it.runIf(process.platform !== "win32")(
    "rejects permissive and symlinked secret files",
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "tabgrant-auth-test-"));
      directories.push(directory);
      const secret = join(directory, "secret");
      await writeFile(secret, randomBytes(32).toString("hex"), { mode: 0o600 });
      await chmod(secret, 0o644);
      await expect(readBrokerSecret(secret)).rejects.toThrow(/unsafe permissions/i);

      const link = join(directory, "secret-link");
      await symlink(secret, link);
      await expect(readBrokerSecret(link)).rejects.toThrow();
    },
  );

  it("persists only an explicitly approved browser public key and no proposal queue", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tabgrant-pairing-test-"));
    directories.push(directory);
    const browser = await browserKeyPair();
    const attacker = await browserKeyPair();
    const browserIdentity = {
      extensionId: "a".repeat(32),
      browserInstanceId: randomUUID(),
      publicKey: browser.publicKey,
    };
    await expect(isPairedBrowserKey(directory, browserIdentity)).resolves.toBe(false);

    await persistApprovedBrowserPairing(directory, browserIdentity);
    await expect(isPairedBrowserKey(directory, browserIdentity)).resolves.toBe(true);
    await expect(
      isPairedBrowserKey(directory, { ...browserIdentity, publicKey: attacker.publicKey }),
    ).resolves.toBe(false);
    expect(await readdir(directory)).toEqual(["browser-pairing.json"]);
  });

  it("accepts only the exact 160-bit extension pairing code shape", async () => {
    const browser = await browserKeyPair();
    const request = {
      extensionId: "a".repeat(32),
      browserInstanceId: randomUUID(),
      publicKey: browser.publicKey,
      pairingCode: "A1B2-C3D4-E5F6-0123-4567-89AB-CDEF-0123-4567-89AB",
    };
    expect(BrowserPairingRequestSchema.parse(request)).toEqual(request);
    expect(() => BrowserPairingRequestSchema.parse({ ...request, pairingCode: "AAAA" })).toThrow();
  });

  it("rejects a wrong key and an expired challenge", async () => {
    const browser = await browserKeyPair();
    const attacker = await browserKeyPair();
    const now = 1_800_000_000_000;
    const challenge = createBrowserAuthChallenge(
      {
        extensionId: "b".repeat(32),
        browserInstanceId: randomUUID(),
        publicKey: browser.publicKey,
      },
      now,
    );
    const signature = await signBrowserChallenge(challenge, browser.privateKey);
    const wrongSignature = await signBrowserChallenge(challenge, attacker.privateKey);
    expect(verifyBrowserAuthSignature(challenge, signature, now)).toBe(true);
    expect(verifyBrowserAuthSignature(challenge, wrongSignature, now)).toBe(false);
    expect(verifyBrowserAuthSignature(challenge, signature, challenge.expiresAt)).toBe(false);
  });
});

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

async function signBrowserChallenge(
  challenge: Parameters<typeof browserAuthPayload>[0],
  privateKey: CryptoKey,
): Promise<string> {
  const signature = await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(browserAuthPayload(challenge)),
  );
  return Buffer.from(signature).toString("base64url");
}
