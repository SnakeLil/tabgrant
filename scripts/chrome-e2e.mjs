import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { access, chmod, cp, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Browser, getInstalledBrowsers } from "@puppeteer/browsers";
import WebSocket from "ws";

const root = fileURLToPath(new URL("..", import.meta.url));
const builtExtensionPath = join(root, "apps", "extension", "dist");
const cliPath = join(root, "apps", "broker", "dist", "cli.js");
const nativeHostPath = join(root, "apps", "broker", "dist", "native-host-entry.js");
const browserCachePath = join(root, ".cache", "tabgrant-browsers");
const chromePath = await findChrome();
const mode = process.argv[2];
if (mode !== "--ci" && mode !== "--manual") {
  throw new Error("Chrome E2E requires exactly one mode: --ci or --manual.");
}
const manualUserPresence = mode === "--manual";
const temporaryDirectory = await mkdtemp(join(tmpdir(), "tabgrant-chrome-e2e-"));
const testExtensionPath = join(temporaryDirectory, "extension");
const profilePath = join(temporaryDirectory, "profile");
const statePath = join(temporaryDirectory, "state");
const profileManifestPath = join(profilePath, "NativeMessagingHosts", "io.tabgrant.bridge.json");
const childEnvironment = { ...process.env, TABGRANT_HOME: statePath };

let chrome;
let daemonChild;
let daemonInstance;
let httpServer;
let mcpClient;
let daemonErrors = () => "";
let expectedExtensionId;
let expectedPairingCode;
let expectedBrowserInstanceId;
let expectedKeyFingerprint;
const pairingApprovals = [];
const childErrorReaders = new WeakMap();

const testPairingApprover = {
  approve: async (request) => {
    pairingApprovals.push(request);
    return (
      pairingApprovals.length === 1 &&
      request.extensionId === expectedExtensionId &&
      request.pairingCode === expectedPairingCode &&
      request.browserInstanceId === expectedBrowserInstanceId &&
      request.keyFingerprint === expectedKeyFingerprint
    );
  },
};

class CdpConnection {
  #socket;
  #nextId = 0;
  #pending = new Map();

  static async open(url) {
    const connection = new CdpConnection(url);
    await connection.#ready();
    await connection.#request("Runtime.enable");
    return connection;
  }

  static async openBrowser(url) {
    const connection = new CdpConnection(url);
    await connection.#ready();
    return connection;
  }

  constructor(url) {
    this.#socket = new WebSocket(url);
    this.#socket.on("message", (data) => {
      const message = JSON.parse(data.toString());
      const resolvePromise = this.#pending.get(message.id);
      if (resolvePromise) {
        this.#pending.delete(message.id);
        resolvePromise(message);
      }
    });
  }

  #ready() {
    return new Promise((resolvePromise, reject) => {
      this.#socket.once("open", resolvePromise);
      this.#socket.once("error", reject);
    });
  }

  #request(method, params = {}) {
    return new Promise((resolvePromise, reject) => {
      const id = ++this.#nextId;
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`CDP ${method} timed out.`));
      }, 10_000);
      this.#pending.set(id, (message) => {
        clearTimeout(timer);
        if (message.error) reject(new Error(`CDP ${method}: ${message.error.message}`));
        else resolvePromise(message.result);
      });
      this.#socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const result = await this.#request("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      const description =
        result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "unknown";
      throw new Error(`CDP evaluation failed: ${description}`);
    }
    return result.result.value;
  }

  request(method, params = {}) {
    return this.#request(method, params);
  }

  close() {
    this.#socket.close();
  }
}

try {
  await assertBuiltArtifacts();
  const page = await startSyntheticPage();
  httpServer = page.server;
  await prepareTestExtension();

  chrome = await startChrome("about:blank");
  const firstPort = await waitForDevToolsPort(chrome);
  const extensionId = await waitForExtensionId(firstPort);
  await stopChild(chrome);
  chrome = undefined;

  await writeDisposableNativeManifest(extensionId);

  if (manualUserPresence) {
    daemonChild = spawn(process.execPath, [cliPath, "daemon", "--quiet"], {
      cwd: root,
      env: childEnvironment,
      stdio: ["ignore", "ignore", "pipe"],
    });
    daemonErrors = captureErrors(daemonChild);
    await waitForPath(join(statePath, "run", "broker.sock"), daemonChild, daemonErrors);
  } else {
    const [{ BrokerDaemon }, { getRuntimePaths }] = await Promise.all([
      import("../apps/broker/src/daemon.ts"),
      import("../apps/broker/src/paths.ts"),
    ]);
    daemonInstance = new BrokerDaemon(getRuntimePaths(childEnvironment), testPairingApprover);
    await daemonInstance.start();
  }

  chrome = await startChrome(page.url, !manualUserPresence);
  const port = await waitForDevToolsPort(chrome);
  const liveExtensionId = await waitForExtensionId(port);
  if (liveExtensionId !== extensionId) throw new Error("Unpacked extension ID changed on restart.");

  mcpClient = await connectMcp();
  const pageTarget = await waitForTarget(port, (target) => target.url === page.url);
  if (manualUserPresence) await maximizeBrowserWindow(port, pageTarget.id);
  await activateTarget(port, pageTarget.id);
  const workerTarget = await waitForTarget(
    port,
    (target) =>
      target.type === "service_worker" &&
      target.url.startsWith(`chrome-extension://${extensionId}/`),
  );
  const worker = await CdpConnection.open(workerTarget.webSocketDebuggerUrl);
  try {
    await worker.evaluate("chrome.action.openPopup()");
  } finally {
    worker.close();
  }
  const popupTarget = await waitForTarget(
    port,
    (target) => target.url === `chrome-extension://${extensionId}/popup.html`,
  );
  let popup = await CdpConnection.open(popupTarget.webSocketDebuggerUrl);
  let pairingCode;
  try {
    pairingCode = await waitForPairingCode(popup);
    const identity = await readPairingIdentity(popup);
    expectedExtensionId = extensionId;
    expectedPairingCode = pairingCode;
    expectedBrowserInstanceId = identity.browserInstanceId;
    expectedKeyFingerprint = identity.keyFingerprint;
    await assertPathAbsent(join(statePath, "browser-pairing-proposals.json"));
    await assertPathAbsent(join(statePath, "browser-pairing.json"));
    if (manualUserPresence) {
      process.stdout.write(
        "TABGRANT_MANUAL_PAIRING_READY: compare the full one-time code, then click Pair in the TabGrant system dialog.\n",
      );
    }
    const pairingStarted = await popup.evaluate(`(() => {
      const button = document.getElementById("pair");
      if (!(button instanceof HTMLButtonElement)) return false;
      button.click();
      return true;
    })()`);
    if (pairingStarted !== true) throw new Error("Could not start browser-key pairing.");
    await waitForBrowserConnection(
      mcpClient,
      port,
      extensionId,
      popup,
      manualUserPresence ? 140 : 150,
      manualUserPresence ? 500 : 50,
    );
    const pairingFile = await readFile(join(statePath, "browser-pairing.json"), "utf8");
    if (
      pairingFile.includes(pairingCode) ||
      pairingFile.includes(pairingCode.replaceAll("-", ""))
    ) {
      throw new Error("Broker persisted the raw browser pairing code.");
    }
    if (!pairingFile.includes(identity.keyFingerprint)) {
      throw new Error("Broker did not bind the paired browser key fingerprint.");
    }
    if (!manualUserPresence && pairingApprovals.length !== 1) {
      throw new Error(`Expected one injected pairing approval, got ${pairingApprovals.length}.`);
    }
  } catch (error) {
    popup.close();
    throw error;
  }

  if (manualUserPresence) {
    await popup.evaluate("window.close()").catch(() => undefined);
    popup.close();
    await waitForTargetAbsent(
      port,
      (target) => target.url === `chrome-extension://${extensionId}/popup.html`,
    );
  }

  const accessRequest = await callToolJson(mcpClient, "browser_access_request", {
    reason: "Synthetic disposable-profile Chrome end-to-end test",
  });
  if (accessRequest.status !== "pending") throw new Error("Access request was not pending.");

  if (manualUserPresence) {
    process.stdout.write(
      "TABGRANT_MANUAL_TOOLBAR_READY: click the TabGrant toolbar action in the disposable Chrome for Testing window.\n",
    );
    const manualPopupTarget = await waitForTarget(
      port,
      (target) => target.url === `chrome-extension://${extensionId}/popup.html`,
      2_400,
    );
    popup = await CdpConnection.open(manualPopupTarget.webSocketDebuggerUrl);
  }

  let lease;
  try {
    const popupText = await waitForPopupRequest(popup);
    if (
      !popupText.includes("Client-declared model provider: synthetic-model") ||
      !popupText.includes("cannot enforce what the client does next")
    ) {
      throw new Error("Popup omitted the declared-provider security warning.");
    }
    if (manualUserPresence) {
      process.stdout.write(
        "TABGRANT_MANUAL_GRANT_READY: click Grant current tab in the TabGrant popup.\n",
      );
      lease = await waitForLease(mcpClient, popup, 240, 500);
    } else {
      const clicked = await popup.evaluate(`(() => {
        const button = [...document.querySelectorAll("button")]
          .find((candidate) => candidate.textContent?.includes("Grant current tab"));
        if (!(button instanceof HTMLButtonElement)) return false;
        button.click();
        return true;
      })()`);
      if (clicked !== true) throw new Error("Could not click the synthetic grant button.");
      lease = await waitForLease(mcpClient, popup);
    }
  } finally {
    popup.close();
  }

  const snapshot = await callToolJson(mcpClient, "browser_snapshot", {
    lease_id: lease.leaseId,
    max_nodes: 200,
  });
  const serializedSnapshot = JSON.stringify(snapshot);
  if (!serializedSnapshot.includes("Synthetic account dashboard")) {
    throw new Error("Real Chrome snapshot did not contain the synthetic heading.");
  }
  if (serializedSnapshot.includes("never-export-this-value")) {
    throw new Error("Real Chrome snapshot exported a password value.");
  }
  if (!snapshot.nodes?.some((node) => node.sensitive === true)) {
    throw new Error("Real Chrome snapshot did not mark the password control as sensitive.");
  }

  const heading = snapshot.nodes.find((node) => node.name === "Synthetic account dashboard");
  await callToolJson(mcpClient, "browser_highlight", {
    lease_id: lease.leaseId,
    ref: heading.ref,
    epoch: snapshot.epoch,
  });
  await callToolJson(mcpClient, "browser_scroll", { lease_id: lease.leaseId, delta_y: 120 });
  await callToolJson(mcpClient, "browser_access_revoke", { lease_id: lease.leaseId });
  const finalStatus = await callToolJson(mcpClient, "browser_access_status", {});
  if (finalStatus.leases.some((candidate) => candidate.active === true)) {
    throw new Error("Lease remained active after revoke.");
  }

  const audit = await readFile(join(statePath, "audit.jsonl"), "utf8");
  if (
    audit.includes("never-export-this-value") ||
    audit.includes("Synthetic account dashboard") ||
    audit.includes(pairingCode)
  ) {
    throw new Error("Audit log contained synthetic page content or browser pairing material.");
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        browser: chromePath,
        extensionId,
        tools: 9,
        snapshotNodes: snapshot.nodes.length,
        passwordValueExported: false,
        nonExtractableBrowserKeyPairingVerified: true,
        injectedPairingApproverVerified: !manualUserPresence,
        osPairingUserPresenceVerified: manualUserPresence,
        globalNativeManifestTouched: false,
        revoked: true,
        syntheticLoopbackHostPermission: !manualUserPresence,
        realActiveTabGestureVerified: manualUserPresence,
        realPopupGrantClickVerified: manualUserPresence,
      },
      null,
      2,
    )}\n`,
  );
} catch (error) {
  const chromeErrors = chrome ? (childErrorReaders.get(chrome)?.() ?? "") : "";
  if (chromeErrors) process.stderr.write(`Chrome diagnostics:\n${chromeErrors}\n`);
  const brokerErrors = daemonErrors();
  if (brokerErrors) process.stderr.write(`Broker diagnostics:\n${brokerErrors}\n`);
  throw error;
} finally {
  await mcpClient?.close().catch(() => undefined);
  await stopChild(chrome);
  await stopChild(daemonChild);
  await daemonInstance?.stop().catch(() => undefined);
  if (httpServer) await new Promise((resolve) => httpServer.close(resolve));
  if (temporaryDirectory.startsWith(`${tmpdir()}${sep}tabgrant-chrome-e2e-`)) {
    await rm(temporaryDirectory, { recursive: true, force: true });
  } else {
    process.stderr.write(`TabGrant E2E refused to clean unexpected path: ${temporaryDirectory}\n`);
  }
}

async function assertBuiltArtifacts() {
  const manifest = JSON.parse(await readFile(join(builtExtensionPath, "manifest.json"), "utf8"));
  if (manifest.name !== "TabGrant" || manifest.manifest_version !== 3) {
    throw new Error("Build the current TabGrant MV3 extension before running Chrome E2E.");
  }
  if ("host_permissions" in manifest) {
    throw new Error("The production extension must not declare persistent host permissions.");
  }
  await Promise.all([access(cliPath), access(nativeHostPath)]);
}

async function prepareTestExtension() {
  await cp(builtExtensionPath, testExtensionPath, {
    recursive: true,
    force: false,
    errorOnExist: true,
  });
  if (manualUserPresence) return;
  const path = join(testExtensionPath, "manifest.json");
  const manifest = JSON.parse(await readFile(path, "utf8"));
  manifest.host_permissions = ["http://127.0.0.1/*"];
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
}

async function writeDisposableNativeManifest(extensionId) {
  await mkdir(join(profilePath, "NativeMessagingHosts"), { recursive: true, mode: 0o700 });
  await chmod(nativeHostPath, 0o755);
  const manifest = {
    name: "io.tabgrant.bridge",
    description: "TabGrant disposable Chrome E2E bridge",
    path: nativeHostPath,
    type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`],
  };
  await writeFile(profileManifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
}

function startSyntheticPage() {
  return new Promise((resolvePromise, reject) => {
    const server = createServer((_request, response) => {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(`<!doctype html><html><body>
        <main>
          <h1>Synthetic account dashboard</h1>
          <p>Disposable test content only</p>
          <label>Password <input type="password" value="never-export-this-value" autocomplete="current-password"></label>
          <button type="button">Review synthetic report</button>
        </main>
      </body></html>`);
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("No test server port."));
      resolvePromise({ server, url: `http://127.0.0.1:${address.port}/` });
    });
  });
}

async function startChrome(url, headless = true) {
  await rm(join(profilePath, "DevToolsActivePort"), { force: true });
  const child = spawn(
    chromePath,
    [
      ...(headless ? ["--headless=new"] : ["--start-maximized"]),
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--enable-unsafe-extension-debugging",
      "--enable-logging=stderr",
      `--user-data-dir=${profilePath}`,
      `--disable-extensions-except=${testExtensionPath}`,
      `--load-extension=${testExtensionPath}`,
      "--remote-debugging-port=0",
      url,
    ],
    { cwd: root, env: childEnvironment, stdio: ["ignore", "ignore", "pipe"] },
  );
  childErrorReaders.set(child, captureErrors(child));
  return child;
}

async function waitForDevToolsPort(child) {
  const path = join(profilePath, "DevToolsActivePort");
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(
        `Chrome exited before publishing DevTools: ${childErrorReaders.get(child)?.() ?? ""}`,
      );
    }
    try {
      const [port] = (await readFile(path, "utf8")).split("\n");
      if (/^\d+$/.test(port)) return Number(port);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await delay(25);
  }
  throw new Error("Chrome did not publish a DevTools port for its disposable profile.");
}

async function waitForExtensionId(port) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const targets = await listTargets(port);
    for (const target of targets) {
      const match = /^chrome-extension:\/\/([a-p]{32})\//.exec(target.url);
      if (!match?.[1] || target.type !== "service_worker") continue;
      const connection = await CdpConnection.open(target.webSocketDebuggerUrl).catch(
        () => undefined,
      );
      if (!connection) continue;
      try {
        const name = await connection.evaluate("chrome.runtime.getManifest().name");
        if (name === "TabGrant") return match[1];
      } catch {
        // Component extensions can expose targets that disappear while Chrome starts.
      } finally {
        connection.close();
      }
    }
    await delay(25);
  }
  throw new Error("Chrome did not load the TabGrant service worker.");
}

async function connectMcp() {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      cliPath,
      "mcp",
      "--client-id",
      "chrome-e2e",
      "--declared-model-provider",
      "synthetic-model",
      "--task-id",
      "chrome-e2e-task",
    ],
    cwd: root,
    env: childEnvironment,
    stderr: "pipe",
    maxBufferSize: 1_048_576,
  });
  const client = new Client({ name: "tabgrant-chrome-e2e", version: "0.1.0" });
  await client.connect(transport);
  const tools = await client.listTools();
  if (tools.tools.length !== 9) throw new Error(`Expected 9 MCP tools, got ${tools.tools.length}.`);
  return client;
}

async function waitForBrowserConnection(
  client,
  port,
  extensionId,
  popup,
  attempts = 150,
  intervalMs = 50,
) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const status = await callToolJson(client, "tabgrant_status", {});
    if (status.browserConnected === true) return;
    const popupDiagnostic = await readPopupPairingDiagnostic(popup).catch(() => undefined);
    if (popupDiagnostic?.error) {
      const pairingState = await describePairingState();
      throw new Error(
        `TabGrant browser pairing failed in the popup: ${popupDiagnostic.error}; ${pairingState}`,
      );
    }
    await delay(intervalMs);
  }
  const diagnostic = await diagnoseNativeMessaging(port, extensionId).catch(
    (error) => `diagnostic failed: ${error.message}`,
  );
  const popupDiagnostic = await readPopupPairingDiagnostic(popup).catch(() => undefined);
  const pairingState = await describePairingState();
  throw new Error(
    `TabGrant extension did not connect through Native Messaging: ${diagnostic}; popup=${JSON.stringify(popupDiagnostic)}; ${pairingState}`,
  );
}

async function readPopupPairingDiagnostic(connection) {
  return connection.evaluate(`(() => {
    const error = document.getElementById("error");
    const brokerStatus = document.getElementById("broker-status");
    const pairingSection = document.getElementById("pairing-section");
    return {
      error: error && !error.hidden ? error.textContent?.trim() ?? "" : "",
      brokerStatus: brokerStatus?.textContent?.trim() ?? "",
      pairingVisible: pairingSection instanceof HTMLElement && !pairingSection.hidden,
    };
  })()`);
}

async function describePairingState() {
  const pairingPath = join(statePath, "browser-pairing.json");
  try {
    const pairing = JSON.parse(await readFile(pairingPath, "utf8"));
    return `pairingFile=present(extensionId=${String(pairing.extensionId ?? "unknown")}, fingerprint=${typeof pairing.fingerprint === "string" ? "present" : "missing"})`;
  } catch (error) {
    if (error.code === "ENOENT") return "pairingFile=absent";
    return `pairingFile=unreadable(${error.message})`;
  }
}

async function diagnoseNativeMessaging(port, extensionId) {
  const target = await waitForTarget(
    port,
    (candidate) =>
      candidate.type === "service_worker" &&
      candidate.url.startsWith(`chrome-extension://${extensionId}/`),
  );
  const connection = await CdpConnection.open(target.webSocketDebuggerUrl);
  try {
    return await connection.evaluate(`new Promise((resolve) => {
      const nativePort = chrome.runtime.connectNative("io.tabgrant.bridge");
      const timer = setTimeout(() => {
        nativePort.disconnect();
        resolve("connected for two seconds");
      }, 2000);
      nativePort.onDisconnect.addListener(() => {
        clearTimeout(timer);
        resolve(chrome.runtime.lastError?.message ?? "disconnected without a runtime error");
      });
    })`);
  } finally {
    connection.close();
  }
}

async function waitForPopupRequest(connection) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    const text = await connection.evaluate('document.body?.innerText ?? ""');
    if (typeof text === "string" && text.includes("Grant current tab")) return text;
    await delay(50);
  }
  throw new Error("TabGrant popup did not render the pending access request.");
}

async function waitForPairingCode(connection) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    const code = await connection.evaluate(
      'document.getElementById("pairing-code")?.textContent?.trim() ?? ""',
    );
    if (typeof code === "string" && /^[A-F0-9]{4}(?:-[A-F0-9]{4}){9}$/.test(code)) return code;
    await delay(50);
  }
  throw new Error("TabGrant popup did not expose an extension-generated pairing code.");
}

async function readPairingIdentity(connection) {
  const identity = await connection.evaluate(`(async () => {
    const stored = await chrome.storage.local.get("tabGrant.browserInstanceId");
    const browserInstanceId = stored["tabGrant.browserInstanceId"];
    const database = await new Promise((resolve, reject) => {
      const request = indexedDB.open("tabGrant.browserAuthority.v1", 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Could not open key database."));
    });
    try {
      const keyPair = await new Promise((resolve, reject) => {
        const transaction = database.transaction("keys", "readonly");
        const request = transaction.objectStore("keys").get("browser-signing-key");
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("Could not read browser key."));
      });
      if (!(keyPair?.publicKey instanceof CryptoKey)) throw new Error("Browser key is missing.");
      const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const canonical = JSON.stringify({
        crv: publicKey.crv,
        kty: publicKey.kty,
        x: publicKey.x,
        y: publicKey.y,
      });
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
      const keyFingerprint = [...new Uint8Array(digest)]
        .map((value) => value.toString(16).padStart(2, "0"))
        .join("");
      return { browserInstanceId, keyFingerprint };
    } finally {
      database.close();
    }
  })()`);
  if (
    !identity ||
    typeof identity.browserInstanceId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      identity.browserInstanceId,
    ) ||
    typeof identity.keyFingerprint !== "string" ||
    !/^[a-f0-9]{64}$/.test(identity.keyFingerprint)
  ) {
    throw new Error("Could not verify the extension browser pairing identity.");
  }
  return identity;
}

async function waitForLease(client, popup, attempts = 150, intervalMs = 50) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const status = await callToolJson(client, "browser_access_status", {});
    const lease = status.leases?.find((candidate) => candidate.active === true);
    const popupState = await popup
      .evaluate(
        `(async () => {
        const error = document.getElementById("error");
        const errorText = error && !error.hidden ? error.textContent : "";
        if (!errorText) return { text: document.body?.innerText ?? "" };
        const tabs = await chrome.tabs.query({});
        return {
          error: errorText,
          text: document.body?.innerText ?? "",
          tabs: tabs.map((tab) => ({
            id: tab.id,
            active: tab.active,
            windowId: tab.windowId,
            url: tab.url,
          })),
        };
      })()`,
      )
      .catch(() => undefined);
    if (popupState?.error)
      throw new Error(`Extension rejected the grant: ${JSON.stringify(popupState)}`);
    if (lease && popupState?.text?.includes("Access active")) return lease;
    await delay(intervalMs);
  }
  throw new Error("The extension did not grant a live lease.");
}

async function callToolJson(client, name, args) {
  const result = await client.callTool({ name, arguments: args });
  const block = result.content.find((candidate) => candidate.type === "text");
  if (!block || block.type !== "text") throw new Error(`${name} returned no text result.`);
  const parsed = JSON.parse(block.text);
  if (result.isError) throw new Error(`${name} failed: ${block.text}`);
  return parsed;
}

async function waitForPath(path, child, errors) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Broker exited early: ${errors()}`);
    try {
      const metadata = await stat(path);
      if (metadata.isSocket()) return;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await delay(25);
  }
  throw new Error("Broker socket did not become ready.");
}

async function assertPathAbsent(path) {
  try {
    await stat(path);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`Unexpected legacy or premature pairing state at ${path}.`);
}

function captureErrors(child) {
  let errors = "";
  child.stderr?.on("data", (chunk) => {
    errors = `${errors}${chunk.toString()}`.slice(-16_384);
  });
  return () => errors;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exitPromise = new Promise((resolvePromise) => child.once("exit", resolvePromise));
  child.kill("SIGTERM");
  const exited = await Promise.race([exitPromise.then(() => true), delay(3_000).then(() => false)]);
  if (!exited) {
    child.kill("SIGKILL");
    if (child.exitCode === null && child.signalCode === null) await exitPromise;
  }
}

async function listTargets(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`);
  if (!response.ok) throw new Error(`Chrome target listing failed: ${response.status}`);
  return response.json();
}

async function waitForTarget(port, predicate, attempts = 150) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const target = (await listTargets(port)).find(predicate);
    if (target) return target;
    await delay(50);
  }
  throw new Error("Expected Chrome target did not appear.");
}

async function waitForTargetAbsent(port, predicate) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (!(await listTargets(port)).some(predicate)) return;
    await delay(50);
  }
  throw new Error("Chrome extension popup did not close before the manual toolbar check.");
}

async function activateTarget(port, id) {
  const response = await fetch(`http://127.0.0.1:${port}/json/activate/${id}`);
  if (!response.ok) throw new Error(`Chrome target activation failed: ${response.status}`);
}

async function maximizeBrowserWindow(port, targetId) {
  const response = await fetch(`http://127.0.0.1:${port}/json/version`);
  if (!response.ok) throw new Error(`Chrome version endpoint failed: ${response.status}`);
  const version = await response.json();
  if (typeof version.webSocketDebuggerUrl !== "string") {
    throw new Error("Chrome did not expose its browser debugger endpoint.");
  }
  const connection = await CdpConnection.openBrowser(version.webSocketDebuggerUrl);
  try {
    const { windowId } = await connection.request("Browser.getWindowForTarget", { targetId });
    await connection.request("Browser.setWindowBounds", {
      windowId,
      bounds: { windowState: "maximized" },
    });
  } finally {
    connection.close();
  }
}

async function findChrome() {
  const configured = process.env.TABGRANT_CHROME_PATH;
  const installed = await getInstalledBrowsers({ cacheDir: browserCachePath }).catch(() => []);
  const cachedChrome = installed
    .filter((browser) => browser.browser === Browser.CHROME)
    .sort((left, right) => right.buildId.localeCompare(left.buildId, undefined, { numeric: true }))
    .map((browser) => browser.executablePath);
  const candidates = configured
    ? [configured]
    : [
        ...cachedChrome,
        ...(platform() === "darwin"
          ? [
              "/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
              "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]
          : ["/usr/bin/chromium", "/usr/bin/chromium-browser"]),
      ];
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next known executable.
    }
  }
  throw new Error(
    "Chrome for Testing or Chromium was not found. Run `pnpm e2e:chrome:install` or set TABGRANT_CHROME_PATH.",
  );
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}
