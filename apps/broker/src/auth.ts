import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, chmod, lstat, mkdir, open, rename } from "node:fs/promises";
import { platform } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";

export const ClientRoleSchema = z.enum(["agent", "browser"]);
export type ClientRole = z.infer<typeof ClientRoleSchema>;

export const AuthHelloSchema = z
  .object({
    role: ClientRoleSchema,
    clientId: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[a-zA-Z0-9._:-]+$/),
    taskId: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[a-zA-Z0-9._:-]+$/),
    instanceId: z.string().uuid(),
    nonce: z.string().regex(/^[a-f0-9]{32}$/),
    timestamp: z.number().int().positive(),
    proof: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export type AuthHello = z.infer<typeof AuthHelloSchema>;

export const BrowserPublicKeyJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    y: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  })
  .strict();
export type BrowserPublicKeyJwk = z.infer<typeof BrowserPublicKeyJwkSchema>;

const ExtensionIdSchema = z.string().regex(/^[a-p]{32}$/);
const BrowserInstanceIdSchema = z.string().uuid();

export const BrowserAuthStartSchema = z
  .object({
    extensionId: ExtensionIdSchema,
    browserInstanceId: BrowserInstanceIdSchema,
    publicKey: BrowserPublicKeyJwkSchema,
  })
  .strict();
export type BrowserAuthStart = z.infer<typeof BrowserAuthStartSchema>;

export const BrowserPairingRequestSchema = BrowserAuthStartSchema.extend({
  pairingCode: z.string().regex(/^[A-F0-9]{4}(?:-[A-F0-9]{4}){9}$/),
}).strict();
export type BrowserPairingRequest = z.infer<typeof BrowserPairingRequestSchema>;

export const BrowserAuthCompleteSchema = z
  .object({
    challengeId: z.string().uuid(),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict();

export interface BrowserAuthChallenge {
  readonly challengeId: string;
  readonly challenge: string;
  readonly extensionId: string;
  readonly browserInstanceId: string;
  readonly publicKey: BrowserPublicKeyJwk;
  readonly expiresAt: number;
}

const BrowserPairingSchema = z
  .object({
    version: z.literal(1),
    extensionId: ExtensionIdSchema,
    publicKey: BrowserPublicKeyJwkSchema,
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    pairedAt: z.string().datetime({ offset: true }),
  })
  .strict();

export interface PairingApprovalRequest {
  readonly extensionId: string;
  readonly browserInstanceId: string;
  readonly pairingCode: string;
  readonly keyFingerprint: string;
}

export interface PairingApprover {
  approve(request: PairingApprovalRequest): Promise<boolean>;
}

const BROWSER_CHALLENGE_TTL_MS = 30_000;

function payloadFor(input: Omit<AuthHello, "proof">): string {
  return [
    input.role,
    input.clientId,
    input.taskId,
    input.instanceId,
    input.nonce,
    input.timestamp,
  ].join("\n");
}

export async function ensureBrokerSecret(secretPath: string): Promise<Buffer> {
  const directory = dirname(secretPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryMetadata = await lstat(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error(`Refusing insecure TabGrant secret directory: ${directory}`);
  }
  assertOwnedByCurrentUser(directory, directoryMetadata.uid);
  await chmod(directory, 0o700);
  try {
    return await readBrokerSecret(secretPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      throw error;
    }
  }

  const secret = randomBytes(32);
  try {
    const handle = await open(secretPath, "wx", 0o600);
    try {
      await handle.writeFile(secret.toString("hex"), { encoding: "utf8" });
    } finally {
      await handle.close();
    }
    return secret;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return readBrokerSecret(secretPath);
    }
    throw error;
  }
}

export async function readBrokerSecret(secretPath: string): Promise<Buffer> {
  const handle = await open(
    secretPath,
    process.platform === "win32" ? constants.O_RDONLY : constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  let value: string;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) {
      throw new Error(`The TabGrant broker secret is not a regular file: ${secretPath}`);
    }
    assertOwnedByCurrentUser(secretPath, metadata.uid);
    if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
      throw new Error(`The TabGrant broker secret has unsafe permissions: ${secretPath}`);
    }
    value = (await handle.readFile({ encoding: "utf8" })).trim();
  } finally {
    await handle.close();
  }
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new Error("The TabGrant broker secret is malformed.");
  }
  return Buffer.from(value, "hex");
}

export function deriveBrokerSecret(secret: Buffer, purpose: string): Buffer {
  if (secret.byteLength < 32 || !/^[a-z0-9./-]{1,128}$/.test(purpose)) {
    throw new Error("Invalid TabGrant key derivation input.");
  }
  return createHmac("sha256", secret).update(`tabgrant/${purpose}/v0.1`).digest();
}

function assertOwnedByCurrentUser(path: string, uid: number): void {
  if (typeof process.getuid === "function" && uid !== process.getuid()) {
    throw new Error(`Refusing TabGrant path owned by another user: ${path}`);
  }
}

export function createAuthHello(
  secret: Buffer,
  identity: Pick<AuthHello, "role" | "clientId" | "taskId" | "instanceId">,
  now = Date.now(),
): AuthHello {
  const unsigned = {
    ...identity,
    nonce: randomBytes(16).toString("hex"),
    timestamp: now,
  };
  return {
    ...unsigned,
    proof: createHmac("sha256", secret).update(payloadFor(unsigned)).digest("hex"),
  };
}

export function verifyAuthHello(
  candidate: unknown,
  secret: Buffer,
  usedNonces: Set<string>,
  now = Date.now(),
): AuthHello {
  const hello = AuthHelloSchema.parse(candidate);
  if (Math.abs(now - hello.timestamp) > 30_000) {
    throw new Error("Authentication timestamp is outside the allowed window.");
  }
  if (usedNonces.has(hello.nonce)) {
    throw new Error("Authentication nonce was already used.");
  }

  const { proof, ...unsigned } = hello;
  const expected = createHmac("sha256", secret).update(payloadFor(unsigned)).digest();
  const supplied = Buffer.from(proof, "hex");
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new Error("Authentication proof is invalid.");
  }

  usedNonces.add(hello.nonce);
  // The user-readable broker secret authenticates only a local agent connection. A caller's
  // claimed role is deliberately ignored; browser authority requires a separately paired key.
  return { ...hello, role: "agent" };
}

export async function persistApprovedBrowserPairing(
  baseDirectory: string,
  input: BrowserAuthStart,
  now = Date.now(),
): Promise<void> {
  const parsed = BrowserAuthStartSchema.parse(input);
  await writePrivateJson(browserPairingPath(baseDirectory), {
    version: 1,
    extensionId: parsed.extensionId,
    publicKey: parsed.publicKey,
    fingerprint: browserPublicKeyFingerprint(parsed.publicKey),
    pairedAt: new Date(now).toISOString(),
  });
}

export function createSystemPairingApprover(): PairingApprover {
  return {
    approve: async (request) => {
      const extensionId = ExtensionIdSchema.parse(request.extensionId);
      const browserInstanceId = BrowserInstanceIdSchema.parse(request.browserInstanceId);
      const pairingCode = z
        .string()
        .regex(/^[A-F0-9]{4}(?:-[A-F0-9]{4}){9}$/)
        .parse(request.pairingCode);
      const keyFingerprint = z
        .string()
        .regex(/^[a-f0-9]{64}$/)
        .parse(request.keyFingerprint);
      const approval = { extensionId, browserInstanceId, pairingCode, keyFingerprint };
      if (platform() === "darwin") return approveWithAppleScript(approval);
      if (platform() === "linux") return approveWithZenity(approval);
      return false;
    },
  };
}

export async function isPairedBrowserKey(
  baseDirectory: string,
  input: BrowserAuthStart,
): Promise<boolean> {
  const parsed = BrowserAuthStartSchema.parse(input);
  let pairing: z.infer<typeof BrowserPairingSchema>;
  try {
    pairing = BrowserPairingSchema.parse(await readPrivateJson(browserPairingPath(baseDirectory)));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  return (
    pairing.extensionId === parsed.extensionId &&
    pairing.fingerprint === browserPublicKeyFingerprint(parsed.publicKey)
  );
}

export function createBrowserAuthChallenge(
  input: BrowserAuthStart,
  now = Date.now(),
): BrowserAuthChallenge {
  const parsed = BrowserAuthStartSchema.parse(input);
  return {
    challengeId: randomUUID(),
    challenge: randomBytes(32).toString("base64url"),
    extensionId: parsed.extensionId,
    browserInstanceId: parsed.browserInstanceId,
    publicKey: parsed.publicKey,
    expiresAt: now + BROWSER_CHALLENGE_TTL_MS,
  };
}

export function browserAuthPayload(challenge: BrowserAuthChallenge): string {
  return [
    "tabgrant/browser-auth/v1",
    challenge.challengeId,
    challenge.challenge,
    challenge.extensionId,
    challenge.browserInstanceId,
    browserPublicKeyFingerprint(challenge.publicKey),
  ].join("\n");
}

export function verifyBrowserAuthSignature(
  challenge: BrowserAuthChallenge,
  signatureInput: string,
  now = Date.now(),
): boolean {
  if (challenge.expiresAt <= now || !/^[A-Za-z0-9_-]{86}$/.test(signatureInput)) return false;
  try {
    const key = createPublicKey({
      key: challenge.publicKey,
      format: "jwk",
    });
    return verify(
      "sha256",
      Buffer.from(browserAuthPayload(challenge), "utf8"),
      { key, dsaEncoding: "ieee-p1363" },
      Buffer.from(signatureInput, "base64url"),
    );
  } catch {
    return false;
  }
}

export function browserPublicKeyFingerprint(publicKey: BrowserPublicKeyJwk): string {
  const parsed = BrowserPublicKeyJwkSchema.parse(publicKey);
  return createHash("sha256")
    .update(JSON.stringify({ crv: parsed.crv, kty: parsed.kty, x: parsed.x, y: parsed.y }))
    .digest("hex");
}

function browserPairingPath(baseDirectory: string): string {
  return join(baseDirectory, "browser-pairing.json");
}

async function approveWithAppleScript(request: PairingApprovalRequest): Promise<boolean> {
  const script = `on run argv
set extensionId to "${request.extensionId}"
set browserInstanceId to "${request.browserInstanceId}"
set pairingCode to "${request.pairingCode}"
set keyFingerprint to "${request.keyFingerprint}"
set messageText to "TabGrant browser pairing request" & return & return & "Extension: " & extensionId & return & "Browser instance: " & browserInstanceId & return & "Pairing code: " & pairingCode & return & "Key fingerprint: " & keyFingerprint
set answer to display dialog messageText buttons {"Deny", "Pair"} default button "Deny" cancel button "Deny" with icon caution giving up after 55
if gave up of answer then return "Deny"
return button returned of answer
end run`;
  try {
    // Feed the dynamic script over stdin so the pairing code is not exposed in process argv.
    const result = await executeFile("/usr/bin/osascript", ["-"], script);
    return result.stdout.trim() === "Pair";
  } catch {
    return false;
  }
}

async function approveWithZenity(request: PairingApprovalRequest): Promise<boolean> {
  const executable = await firstExecutable(["/usr/bin/zenity", "/bin/zenity"]);
  if (executable === undefined) return false;
  const text = [
    "TabGrant browser pairing request",
    `Extension: ${request.extensionId}`,
    `Browser instance: ${request.browserInstanceId}`,
    `Pairing code: ${request.pairingCode}`,
    `Key fingerprint: ${request.keyFingerprint}`,
  ].join("\n");
  try {
    // text-info reads the request from stdin; argv contains no pairing code or identity.
    await executeFile(
      executable,
      [
        "--text-info",
        "--title=TabGrant browser pairing",
        "--ok-label=Pair",
        "--cancel-label=Deny",
        "--timeout=55",
        "--width=720",
        "--height=360",
      ],
      `${text}\n`,
    );
    return true;
  } catch {
    return false;
  }
}

async function firstExecutable(candidates: readonly string[]): Promise<string | undefined> {
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Missing or non-executable user-presence UI fails closed.
    }
  }
  return undefined;
}

function executeFile(
  file: string,
  args: readonly string[],
  stdin?: string,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      file,
      args,
      { encoding: "utf8", timeout: 60_000 },
      (error, stdout, stderr) => {
        if (error) reject(error instanceof Error ? error : new Error("Pairing UI failed."));
        else resolve({ stdout, stderr });
      },
    );
    if (stdin !== undefined) child.stdin?.end(stdin, "utf8");
  });
}

async function readPrivateJson(path: string): Promise<unknown> {
  const handle = await open(
    path,
    process.platform === "win32" ? constants.O_RDONLY : constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error(`Refusing non-regular TabGrant file: ${path}`);
    assertOwnedByCurrentUser(path, metadata.uid);
    if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
      throw new Error(`Refusing permissive TabGrant file: ${path}`);
    }
    return JSON.parse(await handle.readFile({ encoding: "utf8" })) as unknown;
  } finally {
    await handle.close();
  }
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const metadata = await lstat(dirname(path));
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Refusing insecure TabGrant directory: ${dirname(path)}`);
  }
  assertOwnedByCurrentUser(dirname(path), metadata.uid);
  await chmod(dirname(path), 0o700);
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const handle = await open(temporaryPath, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporaryPath, path);
  await chmod(path, 0o600);
}
