import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { platform } from "node:os";
import { dirname } from "node:path";
import type { AuthHello, BrowserAuthChallenge, PairingApprover } from "./auth.js";
import {
  BrowserAuthCompleteSchema,
  BrowserPairingRequestSchema,
  BrowserAuthStartSchema,
  browserPublicKeyFingerprint,
  createBrowserAuthChallenge,
  createSystemPairingApprover,
  deriveBrokerSecret,
  ensureBrokerSecret,
  isPairedBrowserKey,
  persistApprovedBrowserPairing,
  verifyAuthHello,
  verifyBrowserAuthSignature,
} from "./auth.js";
import { AuditLogger } from "./audit.js";
import { BrokerState } from "./broker-state.js";
import { CapabilityIssuer } from "./capability.js";
import { assertKillSwitchDisabled, readKillSwitch } from "./kill-switch.js";
import type { RuntimePaths } from "./paths.js";
import { getRuntimePaths } from "./paths.js";
import { BrokerRpcError, RpcPeer } from "./wire.js";

interface AuthenticatedContext {
  readonly auth: AuthHello;
  readonly peer: RpcPeer;
  browserInstanceId?: string;
}

const PAIRING_PROMPT_COOLDOWN_MS = 30_000;
const PAIRING_ATTEMPT_WINDOW_MS = 5 * 60_000;
const PAIRING_ATTEMPTS_PER_CONNECTION = 3;
const GLOBAL_PAIRING_ATTEMPT_WINDOW_MS = 10 * 60_000;
const GLOBAL_PAIRING_ATTEMPTS = 3;

export class BrokerDaemon {
  private readonly sockets = new Set<Socket>();
  private readonly pendingDisconnects = new Set<Promise<void>>();
  private readonly usedNonces = new Set<string>();
  private server: Server | undefined;
  private state: BrokerState | undefined;
  private secret: Buffer | undefined;
  private killSwitchTimer: NodeJS.Timeout | undefined;
  private pairingPromptActive = false;
  private lastPairingPromptAt: number | undefined;
  private readonly globalPairingAttempts: number[] = [];

  public constructor(
    private readonly paths: RuntimePaths = getRuntimePaths(),
    private readonly pairingApprover: PairingApprover = createSystemPairingApprover(),
    private readonly now: () => number = Date.now,
  ) {}

  public async start(): Promise<void> {
    if (this.server !== undefined) {
      throw new Error("Broker daemon is already running.");
    }
    await assertKillSwitchDisabled(this.paths.killSwitchPath);
    await mkdir(this.paths.runtimeDirectory, { recursive: true, mode: 0o700 });
    const runtimeMetadata = await lstat(this.paths.runtimeDirectory);
    if (!runtimeMetadata.isDirectory() || runtimeMetadata.isSymbolicLink()) {
      throw new Error(
        `Refusing insecure TabGrant runtime directory: ${this.paths.runtimeDirectory}`,
      );
    }
    if (typeof process.getuid === "function" && runtimeMetadata.uid !== process.getuid()) {
      throw new Error(
        `Refusing TabGrant runtime directory owned by another user: ${this.paths.runtimeDirectory}`,
      );
    }
    if (platform() !== "win32") await chmod(this.paths.runtimeDirectory, 0o700);
    await this.removeOwnedStaleSocket();
    this.secret = await ensureBrokerSecret(this.paths.secretPath);
    const authoritySecret = await ensureBrokerSecret(this.paths.authoritySecretPath);
    const audit = new AuditLogger(
      this.paths.auditPath,
      deriveBrokerSecret(authoritySecret, "audit"),
    );
    await audit.initialize();
    this.state = new BrokerState(
      audit,
      new CapabilityIssuer(deriveBrokerSecret(authoritySecret, "capability")),
    );

    const server = createServer((socket) => this.accept(socket));
    server.maxConnections = 64;
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      const handleError = (error: Error): void => reject(error);
      server.once("error", handleError);
      server.listen(this.paths.socketPath, () => {
        server.off("error", handleError);
        resolve();
      });
    });
    if (platform() !== "win32") {
      await chmod(this.paths.socketPath, 0o600);
    }
    this.startKillSwitchMonitor();
  }

  public async stop(): Promise<void> {
    if (this.killSwitchTimer !== undefined) {
      clearInterval(this.killSwitchTimer);
      this.killSwitchTimer = undefined;
    }
    const socketClosures = [...this.sockets].map(
      (socket) => new Promise<void>((resolve) => socket.once("close", resolve)),
    );
    for (const socket of this.sockets) {
      socket.destroy();
    }
    const server = this.server;
    this.server = undefined;
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
    await Promise.all(socketClosures);
    this.sockets.clear();
    await Promise.allSettled([...this.pendingDisconnects]);
    if (platform() !== "win32") {
      try {
        await unlink(this.paths.socketPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
    }
  }

  private accept(socket: Socket): void {
    socket.setNoDelay(true);
    this.sockets.add(socket);
    let context: AuthenticatedContext | undefined;
    let browserChallenge: BrowserAuthChallenge | undefined;
    let browserChallengePairsKey = false;
    const pairingAttempts: number[] = [];

    const peer = new RpcPeer(socket, async (method, params) => {
      if (method === "session.hello") {
        if (context !== undefined) {
          throw new BrokerRpcError("ALREADY_AUTHENTICATED", "Connection is already authenticated.");
        }
        try {
          const auth = verifyAuthHello(params, this.requireSecret(), this.usedNonces);
          context = this.requireState().createContext(auth, peer);
          setTimeout(() => this.usedNonces.delete(auth.nonce), 60_000).unref();
          return { authenticated: true, role: auth.role };
        } catch {
          throw new BrokerRpcError("AUTHENTICATION_FAILED", "Local broker authentication failed.");
        }
      }

      if (context === undefined) {
        throw new BrokerRpcError(
          "AUTHENTICATION_REQUIRED",
          "Authenticate before calling broker methods.",
        );
      }
      if (method === "broker.kill") {
        throw new BrokerRpcError(
          "UNKNOWN_METHOD",
          "Broker kill is a local filesystem control, not an RPC method.",
        );
      }

      if (method === "browser.auth.start") {
        this.requireAgentContext(context);
        const start = BrowserAuthStartSchema.parse(params);
        if (!(await isPairedBrowserKey(this.paths.baseDirectory, start))) {
          browserChallenge = undefined;
          browserChallengePairsKey = false;
          return { paired: false };
        }
        browserChallenge = createBrowserAuthChallenge(start);
        browserChallengePairsKey = false;
        return publicBrowserChallenge(browserChallenge);
      }
      if (method === "browser.auth.pair") {
        this.requireAgentContext(context);
        const pairing = BrowserPairingRequestSchema.parse(params);
        this.reservePairingAttempt(pairingAttempts);
        if (this.pairingPromptActive) {
          throw new BrokerRpcError("BROWSER_PAIRING_BUSY", "Another pairing prompt is active.");
        }
        const now = this.now();
        if (
          this.lastPairingPromptAt !== undefined &&
          now - this.lastPairingPromptAt < PAIRING_PROMPT_COOLDOWN_MS
        ) {
          throw new BrokerRpcError(
            "BROWSER_PAIRING_COOLDOWN",
            "Browser pairing is temporarily rate limited.",
          );
        }
        this.reserveGlobalPairingAttempt();
        this.pairingPromptActive = true;
        let approved: boolean;
        try {
          approved = await this.pairingApprover.approve({
            extensionId: pairing.extensionId,
            browserInstanceId: pairing.browserInstanceId,
            pairingCode: pairing.pairingCode,
            keyFingerprint: browserPublicKeyFingerprint(pairing.publicKey),
          });
        } catch {
          approved = false;
        } finally {
          this.pairingPromptActive = false;
          // Measure cooldown from dismissal, not launch. A timed-out prompt must not permit an
          // immediate replacement prompt from a fresh agent connection.
          this.lastPairingPromptAt = this.now();
        }
        browserChallenge = undefined;
        browserChallengePairsKey = false;
        if (!approved) {
          throw new BrokerRpcError("BROWSER_PAIRING_DENIED", "Browser pairing was not approved.");
        }
        const browserIdentity = {
          extensionId: pairing.extensionId,
          browserInstanceId: pairing.browserInstanceId,
          publicKey: pairing.publicKey,
        };
        const approvedAt = this.now();
        browserChallenge = createBrowserAuthChallenge(browserIdentity, approvedAt);
        browserChallengePairsKey = true;
        return publicBrowserChallenge(browserChallenge);
      }
      if (method === "browser.auth.complete") {
        this.requireAgentContext(context);
        const completion = BrowserAuthCompleteSchema.parse(params);
        const challenge = browserChallenge;
        const pairsKey = browserChallengePairsKey;
        browserChallenge = undefined;
        browserChallengePairsKey = false;
        if (
          challenge === undefined ||
          completion.challengeId !== challenge.challengeId ||
          !verifyBrowserAuthSignature(challenge, completion.signature)
        ) {
          throw new BrokerRpcError(
            "BROWSER_AUTHENTICATION_FAILED",
            "Browser challenge proof was rejected.",
          );
        }
        if (pairsKey) {
          await persistApprovedBrowserPairing(
            this.paths.baseDirectory,
            {
              extensionId: challenge.extensionId,
              browserInstanceId: challenge.browserInstanceId,
              publicKey: challenge.publicKey,
            },
            this.now(),
          );
        }
        await this.requireState().disconnected(context);
        const browserAuth: AuthHello = {
          ...context.auth,
          role: "browser",
          clientId: "tabgrant-extension",
          taskId: "browser-session",
          instanceId: challenge.browserInstanceId,
        };
        context = this.requireState().createContext(browserAuth, peer);
        return { authenticated: true, role: "browser" };
      }
      return this.requireState().handle(context, method, params);
    });

    socket.once("close", () => {
      this.sockets.delete(socket);
      if (context !== undefined) {
        this.trackDisconnect(context);
      }
    });
  }

  private trackDisconnect(context: AuthenticatedContext): void {
    const pending = this.requireState().disconnected(context);
    this.pendingDisconnects.add(pending);
    void pending.then(
      () => this.pendingDisconnects.delete(pending),
      () => {
        this.pendingDisconnects.delete(pending);
        if (this.server !== undefined) void this.stop().catch(() => undefined);
      },
    );
  }

  private requireSecret(): Buffer {
    if (this.secret === undefined) {
      throw new Error("Broker secret is not initialized.");
    }
    return this.secret;
  }

  private requireState(): BrokerState {
    if (this.state === undefined) {
      throw new Error("Broker state is not initialized.");
    }
    return this.state;
  }

  private requireAgentContext(context: AuthenticatedContext): void {
    if (context.auth.role !== "agent") {
      throw new BrokerRpcError("ALREADY_AUTHENTICATED", "Browser connection is already active.");
    }
  }

  private reservePairingAttempt(attempts: number[]): void {
    const now = this.now();
    while (attempts.length > 0 && (attempts[0] ?? now) <= now - PAIRING_ATTEMPT_WINDOW_MS) {
      attempts.shift();
    }
    if (attempts.length >= PAIRING_ATTEMPTS_PER_CONNECTION) {
      throw new BrokerRpcError(
        "BROWSER_PAIRING_RATE_LIMIT",
        "This connection made too many browser pairing attempts.",
      );
    }
    attempts.push(now);
  }

  private reserveGlobalPairingAttempt(): void {
    const now = this.now();
    while (
      this.globalPairingAttempts.length > 0 &&
      (this.globalPairingAttempts[0] ?? now) <= now - GLOBAL_PAIRING_ATTEMPT_WINDOW_MS
    ) {
      this.globalPairingAttempts.shift();
    }
    if (this.globalPairingAttempts.length >= GLOBAL_PAIRING_ATTEMPTS) {
      throw new BrokerRpcError(
        "BROWSER_PAIRING_GLOBAL_RATE_LIMIT",
        "Browser pairing prompts are temporarily rate limited.",
      );
    }
    this.globalPairingAttempts.push(now);
  }

  private startKillSwitchMonitor(): void {
    let checking = false;
    this.killSwitchTimer = setInterval(() => {
      if (checking || this.server === undefined) return;
      checking = true;
      void readKillSwitch(this.paths.killSwitchPath)
        .then((status) => {
          if (status.active) return this.stop();
          return undefined;
        })
        .catch(() => this.stop())
        .finally(() => {
          checking = false;
        });
    }, 200);
    this.killSwitchTimer.unref();
  }

  private async removeOwnedStaleSocket(): Promise<void> {
    if (platform() === "win32") {
      return;
    }
    try {
      const metadata = await lstat(this.paths.socketPath);
      if (!metadata.isSocket()) {
        throw new Error(`Refusing to replace non-socket path: ${this.paths.socketPath}`);
      }
      if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
        throw new Error(
          `Refusing to replace a socket owned by another user: ${this.paths.socketPath}`,
        );
      }
      if (dirname(this.paths.socketPath) !== this.paths.runtimeDirectory) {
        throw new Error("Refusing to unlink a socket outside the TabGrant runtime directory.");
      }
      if (await socketAcceptsConnections(this.paths.socketPath)) {
        throw new BrokerRpcError(
          "BROKER_ALREADY_RUNNING",
          "A TabGrant broker is already listening on this socket.",
        );
      }
      await unlink(this.paths.socketPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }
  }
}

function publicBrowserChallenge(challenge: BrowserAuthChallenge): {
  paired: true;
  challengeId: string;
  challenge: string;
  expiresAt: number;
} {
  return {
    paired: true,
    challengeId: challenge.challengeId,
    challenge: challenge.challenge,
    expiresAt: challenge.expiresAt,
  };
}

function socketAcceptsConnections(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect(path);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
  });
}

export async function runDaemon(paths = getRuntimePaths()): Promise<void> {
  const daemon = new BrokerDaemon(paths);
  await daemon.start();

  let stopping = false;
  const stop = async (): Promise<void> => {
    if (stopping) {
      return;
    }
    stopping = true;
    await daemon.stop();
  };
  process.once("SIGINT", () => void stop().finally(() => process.exit(0)));
  process.once("SIGTERM", () => void stop().finally(() => process.exit(0)));
}
