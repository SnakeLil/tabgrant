import {
  createWireError,
  createWireRequest,
  createWireResponse,
  parseBrowserAuthChallenge,
  parseBrowserExecute,
  parseBrowserPublicKeyJwk,
  parseGrantedLease,
  parsePendingAccessRequest,
  parsePendingList,
  parsePopupRequest,
  parseWireEnvelope,
  type BrowserExecute,
  type BrowserAuthChallengeResponse,
  type BrowserPublicKeyJwk,
  type PendingAccessRequest,
  type PopupState,
  type TabGrant,
  type TabGrantScope,
  type WireEvent,
  type WireRequest,
  type WireResponse,
} from "./protocol.js";
import { grantableOrigin, sameOriginNavigation } from "./security.js";

const NATIVE_HOST = "io.tabgrant.bridge";
const STATE_KEY = "tabGrant.v0.1.wire1";
const BROWSER_INSTANCE_KEY = "tabGrant.browserInstanceId";
const RECONNECT_DELAY_MS = 3_000;
const RPC_TIMEOUT_MS = 15_000;
// The broker's production approval process hard-stops at 60 seconds. Allow
// transport and signature headroom without extending the user-facing prompt.
const PAIRING_RPC_TIMEOUT_MS = 70_000;
const KEY_DATABASE = "tabGrant.browserAuthority.v1";
const KEY_STORE = "keys";
const KEY_RECORD = "browser-signing-key";
const PAIRING_CODE_KEY = "tabGrant.browserPairingCode.v1";

interface StoredState {
  pending: PendingAccessRequest[];
  grant?: TabGrant;
}

interface PendingRpc {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

class ExtensionRpcError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ExtensionRpcError";
  }
}

let nativePort: chrome.runtime.Port | undefined;
let brokerConnected = false;
let brokerKilled = false;
let browserPaired = false;
let browserInstanceId: string | undefined;
let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
let expiryTimer: ReturnType<typeof setTimeout> | undefined;
const pendingRpc = new Map<string, PendingRpc>();

chrome.runtime.onInstalled.addListener(() => void initialize());
chrome.runtime.onStartup.addListener(() => void initialize());
chrome.tabs.onRemoved.addListener((tabId) => void revokeIfTab(tabId, "TAB_CLOSED"));
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading" || changeInfo.url)
    void revokeIfTab(tabId, "DOCUMENT_CHANGED");
});

chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  void handlePopupMessage(raw, sender)
    .then(sendResponse)
    .catch((error: unknown) =>
      sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : "Extension request failed.",
      }),
    );
  return true;
});

void initialize();

async function initialize(): Promise<void> {
  browserInstanceId = await getBrowserInstanceId();
  const state = await pruneExpiredState();
  scheduleExpiry(state.grant);
  await updateBadge(state);
  connectNative();
}

function connectNative(): void {
  if (nativePort) return;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = undefined;
  brokerConnected = false;

  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    nativePort = port;
    port.onMessage.addListener((message: unknown) => void receiveNativeMessage(port, message));
    port.onDisconnect.addListener(() => void handleNativeDisconnect(port));
    void registerBrowser(port);
  } catch {
    nativePort = undefined;
    scheduleReconnect();
  }
}

async function registerBrowser(port: chrome.runtime.Port): Promise<void> {
  try {
    const instanceId = browserInstanceId ?? (await getBrowserInstanceId());
    browserInstanceId = instanceId;
    if (!(await authenticateBrowser(instanceId))) {
      browserPaired = false;
      await broadcastState();
      return;
    }
    browserPaired = true;
    await registerAuthenticatedBrowser(port, instanceId);
  } catch {
    if (nativePort === port) {
      brokerConnected = false;
      await broadcastState();
      port.disconnect();
    }
  }
}

async function registerAuthenticatedBrowser(
  port: chrome.runtime.Port,
  instanceId: string,
): Promise<void> {
  try {
    await requestBroker("browser.register", {
      browserInstanceId: instanceId,
      extensionId: chrome.runtime.id,
      browserName: "Chromium",
      browserVersion: chrome.runtime.getManifest().version,
    });
    const pendingResult = await requestBroker("access.pending.list", {});
    const pending = parsePendingList(pendingResult);
    if (!pending)
      throw new ExtensionRpcError(
        "INVALID_BROKER_RESPONSE",
        "Broker returned an invalid pending list.",
      );
    if (nativePort !== port) return;
    brokerConnected = true;
    brokerKilled = false;
    const state = await readState();
    await writeState({ ...state, pending });
    await broadcastState();
  } catch {
    if (nativePort === port) {
      brokerConnected = false;
      await broadcastState();
      port.disconnect();
    }
  }
}

async function handleNativeDisconnect(port: chrome.runtime.Port): Promise<void> {
  void chrome.runtime.lastError;
  if (nativePort !== port) return;
  nativePort = undefined;
  brokerConnected = false;
  rejectPendingRpc(new ExtensionRpcError("BROKER_DISCONNECTED", "Native broker disconnected."));
  const state = await readState();
  if (state.grant) await revokeGrant(state.grant.leaseId, "BROKER_DISCONNECTED", false);
  else await broadcastState();
  scheduleReconnect();
}

function scheduleReconnect(): void {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = undefined;
    connectNative();
  }, RECONNECT_DELAY_MS);
}

async function receiveNativeMessage(port: chrome.runtime.Port, raw: unknown): Promise<void> {
  const envelope = parseWireEnvelope(raw);
  if (!envelope) return;
  if (envelope.kind === "response") {
    settleBrokerResponse(envelope);
    return;
  }
  if (envelope.kind === "event") {
    await handleBrokerEvent(envelope);
    return;
  }
  await handleBrokerRequest(port, envelope);
}

function settleBrokerResponse(response: WireResponse): void {
  const pending = pendingRpc.get(response.id);
  if (!pending) return;
  clearTimeout(pending.timer);
  pendingRpc.delete(response.id);
  if (response.ok) pending.resolve(response.result);
  else
    pending.reject(
      new ExtensionRpcError(
        response.error?.code ?? "BROKER_ERROR",
        response.error?.message ?? "Broker request failed.",
      ),
    );
}

async function handleBrokerRequest(port: chrome.runtime.Port, request: WireRequest): Promise<void> {
  if (request.method !== "browser.execute") {
    postToPort(
      port,
      createWireError(request.id, "UNKNOWN_METHOD", `Unsupported broker method: ${request.method}`),
    );
    return;
  }
  try {
    const command = parseBrowserExecute(request.params);
    if (!command)
      throw new ExtensionRpcError("INVALID_COMMAND", "browser.execute params were rejected.");
    const result = await executeBrowserCommand(command);
    postToPort(port, createWireResponse(request.id, result));
  } catch (error) {
    const rpcError =
      error instanceof ExtensionRpcError
        ? error
        : new ExtensionRpcError(
            "BROWSER_COMMAND_FAILED",
            error instanceof Error ? error.message : "Browser command failed.",
          );
    postToPort(port, createWireError(request.id, rpcError.code, rpcError.message));
  }
}

async function handleBrokerEvent(message: WireEvent): Promise<void> {
  if (message.event === "access.requested") {
    const request = parsePendingAccessRequest(message.payload);
    if (!request) return;
    const state = await pruneExpiredState();
    const pending = [
      request,
      ...state.pending.filter((item) => item.requestId !== request.requestId),
    ].slice(0, 10);
    await writeState({ ...state, pending });
    await broadcastState();
    return;
  }
  if (message.event === "access.revoked") {
    const payload = parseRevokedEvent(message.payload);
    if (!payload) return;
    await revokeGrant(payload.leaseId, payload.reason, false);
    return;
  }
  if (message.event === "broker.killed") {
    if (!isEmptyRecord(message.payload)) return;
    brokerKilled = true;
    const state = await readState();
    await writeState({ ...state, pending: [] });
    if (state.grant) await revokeGrant(state.grant.leaseId, "KILL_SWITCH", false);
    else await broadcastState();
  }
}

async function executeBrowserCommand(command: BrowserExecute): Promise<unknown> {
  const state = await pruneExpiredState();
  const grant = state.grant;
  if (!brokerConnected || brokerKilled || !grant || !leaseMatchesGrant(command.lease, grant)) {
    throw new ExtensionRpcError("LEASE_MISMATCH", "No matching active document grant exists.");
  }
  if (command.lease.expiresAt <= Date.now()) {
    await revokeGrant(grant.leaseId, "LEASE_EXPIRED", false);
    throw new ExtensionRpcError("LEASE_EXPIRED", "The document grant has expired.");
  }
  requireCommandScopes(command);

  const tab = await chrome.tabs.get(grant.tabId).catch(() => undefined);
  if (!tab?.url || grantableOrigin(tab.url) !== grant.origin) {
    await revokeGrant(grant.leaseId, "ORIGIN_CHANGED", true);
    throw new ExtensionRpcError("ORIGIN_CHANGED", "The tab is no longer at its granted origin.");
  }
  await assertDocumentIdentity(grant);

  if (command.command === "navigate") {
    const target = sameOriginNavigation(grant.origin, command.args.url);
    if (!target)
      throw new ExtensionRpcError("ORIGIN_CHANGED", "Navigation is limited to the granted origin.");
    await chrome.tabs.update(grant.tabId, { url: target });
    setTimeout(() => void revokeGrant(grant.leaseId, "DOCUMENT_CHANGED", true), 0);
    return { url: target, navigationStarted: true };
  }

  const action =
    command.command === "snapshot"
      ? { type: "snapshot", maxNodes: command.args.maxNodes }
      : command.command === "highlight"
        ? { type: "highlight", ref: command.args.ref, epoch: command.args.epoch }
        : { type: "scroll", deltaY: command.args.deltaY };
  try {
    return await sendBridgeCommand(grant.tabId, grant.documentId, action);
  } catch (error) {
    if (
      error instanceof ExtensionRpcError &&
      ["DOCUMENT_CHANGED", "BRIDGE_UNAVAILABLE", "BRIDGE_REVOKED"].includes(error.code)
    ) {
      await revokeGrant(grant.leaseId, "DOCUMENT_CHANGED", true);
    }
    throw error;
  }
}

function requireCommandScopes(command: BrowserExecute): void {
  const scopes = new Set(command.lease.scopes);
  const required: TabGrantScope[] =
    command.command === "snapshot"
      ? ["page.a11y.read", "data.egress.model"]
      : command.command === "highlight"
        ? ["page.highlight"]
        : command.command === "scroll"
          ? ["page.scroll"]
          : ["page.navigate.same_origin"];
  if (required.some((scope) => !scopes.has(scope))) {
    throw new ExtensionRpcError("SCOPE_REQUIRED", `Command requires ${required.join(" and ")}.`);
  }
}

async function handlePopupMessage(
  raw: unknown,
  sender: chrome.runtime.MessageSender,
): Promise<unknown> {
  if (!isTrustedPopupSender(sender)) return { ok: false, error: "Untrusted extension sender." };
  const request = parsePopupRequest(raw);
  if (!request) return { ok: false, error: "Unknown popup request." };
  if (request.type === "popup.get-state") return { ok: true, state: await popupState() };
  if (request.type === "popup.reconnect") {
    if (nativePort) await registerBrowser(nativePort);
    else connectNative();
    return { ok: true, state: await popupState() };
  }
  if (request.type === "popup.pair") {
    const port = nativePort;
    if (!port) throw new Error("The native broker relay is offline.");
    const instanceId = await pairBrowser();
    await registerAuthenticatedBrowser(port, instanceId);
    return { ok: true, state: await popupState() };
  }
  if (request.type === "popup.grant-current-tab") {
    await grantCurrentTab(request.requestId);
    return { ok: true, state: await popupState() };
  }
  await revokeGrant(request.leaseId, "USER_REVOKED", true);
  return { ok: true, state: await popupState() };
}

function isTrustedPopupSender(sender: chrome.runtime.MessageSender): boolean {
  return (
    sender.id === chrome.runtime.id &&
    sender.tab === undefined &&
    sender.url === chrome.runtime.getURL("popup.html")
  );
}

async function grantCurrentTab(requestId: string): Promise<void> {
  if (!brokerConnected || brokerKilled || !browserInstanceId)
    throw new Error("The broker is not ready.");
  const state = await pruneExpiredState();
  const accessRequest = state.pending.find((item) => item.requestId === requestId);
  if (!accessRequest) throw new Error("The access request is missing or expired.");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined || !tab.url) throw new Error("No eligible active tab is available.");
  const origin = grantableOrigin(tab.url);
  if (!origin || tab.url.length > 2_048)
    throw new Error("Only HTTPS or loopback HTTP tabs can be granted.");
  if (state.grant) await revokeGrant(state.grant.leaseId, "REPLACED", true);

  await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content-bridge.js"] });
  const documentId = await identifyDocument(tab.id);
  let brokerLeaseId: string | undefined;
  try {
    const verifiedTab = await chrome.tabs.get(tab.id);
    const latestState = await readState();
    if (
      !verifiedTab.url ||
      verifiedTab.url !== tab.url ||
      grantableOrigin(verifiedTab.url) !== origin ||
      !latestState.pending.some((item) => item.requestId === requestId) ||
      accessRequest.expiresAt <= Date.now()
    ) {
      throw new Error("The tab or access request changed before the grant could be committed.");
    }

    const leaseResult = await requestBroker("access.grant", {
      requestId,
      browserInstanceId,
      tabId: tab.id,
      documentId,
      origin,
      url: tab.url,
      title: (tab.title ?? "").slice(0, 256),
      scopes: accessRequest.scopes,
      ttlSeconds: 600,
    });
    const lease = parseGrantedLease(leaseResult);
    if (!lease || !grantResultMatches(lease, accessRequest, tab.id, documentId, origin)) {
      throw new ExtensionRpcError("INVALID_BROKER_RESPONSE", "Broker returned a mismatched lease.");
    }
    brokerLeaseId = lease.leaseId;

    const finalTab = await chrome.tabs.get(tab.id);
    if (
      !finalTab.url ||
      finalTab.url !== tab.url ||
      (await identifyDocument(tab.id)) !== documentId
    ) {
      throw new Error("The document changed before the lease became active.");
    }

    const latest = await readState();
    const grant: TabGrant = {
      ...lease,
      url: tab.url,
      title: (tab.title ?? "").slice(0, 256),
    };
    await writeState({
      pending: latest.pending.filter((item) => item.requestId !== requestId),
      grant,
    });
    scheduleExpiry(grant);
    await broadcastState();
  } catch (error) {
    await teardownBridge(tab.id, documentId);
    if (brokerLeaseId)
      void requestBroker("access.revoke", { leaseId: brokerLeaseId, reason: "GRANT_RACE" }).catch(
        () => undefined,
      );
    throw error;
  }
}

async function revokeIfTab(tabId: number, reason: string): Promise<void> {
  const state = await readState();
  if (state.grant?.tabId === tabId) await revokeGrant(state.grant.leaseId, reason, true);
}

async function revokeGrant(leaseId: string, reason: string, notifyBroker: boolean): Promise<void> {
  const state = await readState();
  const grant = state.grant;
  if (!grant || grant.leaseId !== leaseId) return;
  await teardownBridge(grant.tabId, grant.documentId);
  if (expiryTimer) clearTimeout(expiryTimer);
  expiryTimer = undefined;
  const withoutGrant: StoredState = { ...state };
  delete withoutGrant.grant;
  await writeState(withoutGrant);
  await broadcastState();
  if (notifyBroker && nativePort) {
    void requestBroker("access.revoke", { leaseId, reason: reason.slice(0, 64) }).catch(
      () => undefined,
    );
  }
}

async function identifyDocument(tabId: number): Promise<string> {
  const result = await sendRawBridgeCommand(tabId, undefined, { type: "bridge.identify" });
  if (
    !isRecord(result) ||
    typeof result.documentId !== "string" ||
    result.documentId.length > 128
  ) {
    throw new ExtensionRpcError(
      "INVALID_BRIDGE_RESPONSE",
      "Content bridge returned an invalid document ID.",
    );
  }
  return result.documentId;
}

async function assertDocumentIdentity(grant: TabGrant): Promise<void> {
  let currentDocumentId: string;
  try {
    currentDocumentId = await identifyDocument(grant.tabId);
  } catch {
    await revokeGrant(grant.leaseId, "DOCUMENT_CHANGED", true);
    throw new ExtensionRpcError("DOCUMENT_CHANGED", "The granted document is no longer available.");
  }
  if (currentDocumentId !== grant.documentId) {
    await revokeGrant(grant.leaseId, "DOCUMENT_CHANGED", true);
    throw new ExtensionRpcError("DOCUMENT_CHANGED", "The granted document identity changed.");
  }
}

async function sendBridgeCommand(
  tabId: number,
  documentId: string,
  action: unknown,
): Promise<unknown> {
  return sendRawBridgeCommand(tabId, documentId, action);
}

async function sendRawBridgeCommand(
  tabId: number,
  documentId: string | undefined,
  action: unknown,
): Promise<unknown> {
  const requestId = crypto.randomUUID();
  let response: unknown;
  try {
    response = await chrome.tabs.sendMessage(tabId, {
      type: "bridge.command",
      requestId,
      ...(documentId ? { expectedDocumentId: documentId } : {}),
      action,
    });
  } catch {
    throw new ExtensionRpcError(
      "BRIDGE_UNAVAILABLE",
      "The injected document bridge is unavailable.",
    );
  }
  if (!isRecord(response) || response.requestId !== requestId || typeof response.ok !== "boolean") {
    throw new ExtensionRpcError(
      "INVALID_BRIDGE_RESPONSE",
      "Content bridge returned an invalid response.",
    );
  }
  if (!response.ok) {
    const error = isRecord(response.error) ? response.error : undefined;
    throw new ExtensionRpcError(
      typeof error?.code === "string" ? error.code : "BRIDGE_ERROR",
      typeof error?.message === "string" ? error.message : "Content bridge rejected the command.",
    );
  }
  return response.result;
}

async function teardownBridge(tabId: number, documentId: string): Promise<void> {
  try {
    await sendRawBridgeCommand(tabId, documentId, { type: "bridge.teardown" });
  } catch {
    // A closed, navigated, or already torn-down document is effectively revoked.
  }
}

function requestBroker(method: string, params: unknown): Promise<unknown> {
  const port = nativePort;
  if (!port)
    return Promise.reject(
      new ExtensionRpcError("BROKER_DISCONNECTED", "Native broker is unavailable."),
    );
  const request = createWireRequest(method, params);
  const response = new Promise<unknown>((resolve, reject) => {
    const timeoutMs = method === "browser.auth.pair" ? PAIRING_RPC_TIMEOUT_MS : RPC_TIMEOUT_MS;
    const timer = setTimeout(() => {
      pendingRpc.delete(request.id);
      reject(new ExtensionRpcError("BROKER_TIMEOUT", `Timed out waiting for ${method}.`));
    }, timeoutMs);
    pendingRpc.set(request.id, { resolve, reject, timer });
  });
  try {
    port.postMessage(request);
  } catch {
    const pending = pendingRpc.get(request.id);
    if (pending) {
      clearTimeout(pending.timer);
      pendingRpc.delete(request.id);
      pending.reject(
        new ExtensionRpcError("BROKER_DISCONNECTED", "Failed to send native message."),
      );
    }
  }
  return response;
}

function postToPort(port: chrome.runtime.Port, message: unknown): void {
  if (nativePort !== port) return;
  try {
    port.postMessage(message);
  } catch {
    // Disconnect handling rejects active requests and revokes the local lease.
  }
}

function rejectPendingRpc(error: Error): void {
  for (const pending of pendingRpc.values()) {
    clearTimeout(pending.timer);
    pending.reject(error);
  }
  pendingRpc.clear();
}

async function pruneExpiredState(): Promise<StoredState> {
  const state = await readState();
  const now = Date.now();
  const pending = state.pending.filter((item) => item.expiresAt > now);
  if (state.grant && state.grant.expiresAt <= now) {
    await revokeGrant(state.grant.leaseId, "LEASE_EXPIRED", true);
    const next = { pending };
    await writeState(next);
    return next;
  }
  if (pending.length !== state.pending.length) {
    const next = { ...state, pending };
    await writeState(next);
    return next;
  }
  return state;
}

function scheduleExpiry(grant: TabGrant | undefined): void {
  if (expiryTimer) clearTimeout(expiryTimer);
  expiryTimer = undefined;
  if (!grant) return;
  expiryTimer = setTimeout(
    () => void revokeGrant(grant.leaseId, "LEASE_EXPIRED", true),
    Math.max(0, grant.expiresAt - Date.now()),
  );
}

async function popupState(): Promise<PopupState> {
  const state = await pruneExpiredState();
  return {
    brokerConnected,
    brokerKilled,
    browserPaired,
    ...(!browserPaired ? { pairingCode: await getBrowserPairingCode() } : {}),
    pending: state.pending,
    ...(state.grant ? { grant: state.grant } : {}),
  };
}

async function authenticateBrowser(instanceId: string): Promise<boolean> {
  const keys = await getOrCreateBrowserSigningKey();
  const publicKey = await exportBrowserPublicKey(keys.publicKey);
  const result = parseBrowserAuthChallenge(
    await requestBroker("browser.auth.start", {
      extensionId: chrome.runtime.id,
      browserInstanceId: instanceId,
      publicKey,
    }),
  );
  if (!result) {
    throw new ExtensionRpcError(
      "INVALID_BROKER_RESPONSE",
      "Broker returned an invalid browser authentication challenge.",
    );
  }
  if (!result.paired) return false;
  await completeBrowserAuthentication(result, instanceId, publicKey, keys.privateKey);
  await chrome.storage.session.remove(PAIRING_CODE_KEY);
  return true;
}

async function pairBrowser(): Promise<string> {
  const instanceId = browserInstanceId ?? (await getBrowserInstanceId());
  browserInstanceId = instanceId;
  const keys = await getOrCreateBrowserSigningKey();
  const publicKey = await exportBrowserPublicKey(keys.publicKey);
  const pairingCode = await getBrowserPairingCode();
  try {
    const challenge = parseBrowserAuthChallenge(
      await requestBroker("browser.auth.pair", {
        extensionId: chrome.runtime.id,
        browserInstanceId: instanceId,
        publicKey,
        pairingCode,
      }),
    );
    if (!challenge?.paired) {
      throw new ExtensionRpcError("BROWSER_PAIRING_FAILED", "Browser pairing was not approved.");
    }
    await completeBrowserAuthentication(challenge, instanceId, publicKey, keys.privateKey);
    browserPaired = true;
    return instanceId;
  } finally {
    // A displayed code is single-attempt even when the prompt is denied or times out.
    await chrome.storage.session.remove(PAIRING_CODE_KEY).catch(() => undefined);
    await broadcastState().catch(() => undefined);
  }
}

async function completeBrowserAuthentication(
  challenge: Extract<BrowserAuthChallengeResponse, { paired: true }>,
  instanceId: string,
  publicKey: BrowserPublicKeyJwk,
  privateKey: CryptoKey,
): Promise<void> {
  const fingerprint = await publicKeyFingerprint(publicKey);
  const payload = [
    "tabgrant/browser-auth/v1",
    challenge.challengeId,
    challenge.challenge,
    chrome.runtime.id,
    instanceId,
    fingerprint,
  ].join("\n");
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(payload),
  );
  const response = await requestBroker("browser.auth.complete", {
    challengeId: challenge.challengeId,
    signature: base64Url(new Uint8Array(signature)),
  });
  if (
    !isRecord(response) ||
    !isEmptyOrOnlyKeys(response, ["authenticated", "role"]) ||
    response.authenticated !== true ||
    response.role !== "browser"
  ) {
    throw new ExtensionRpcError(
      "INVALID_BROKER_RESPONSE",
      "Broker did not confirm browser authentication.",
    );
  }
}

async function getOrCreateBrowserSigningKey(): Promise<CryptoKeyPair> {
  const database = await openKeyDatabase();
  try {
    const existing = await databaseRequest<unknown>(
      database.transaction(KEY_STORE, "readonly").objectStore(KEY_STORE).get(KEY_RECORD),
    );
    if (isCryptoKeyPair(existing) && existing.privateKey.extractable === false) return existing;

    const generated = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    await databaseTransaction(database, "readwrite", (store) => store.put(generated, KEY_RECORD));
    return generated;
  } finally {
    database.close();
  }
}

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(KEY_STORE)) {
        request.result.createObjectStore(KEY_STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open browser key store."));
  });
}

function databaseRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Browser key operation failed."));
  });
}

function databaseTransaction(
  database: IDBDatabase,
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(KEY_STORE, mode);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Key storage failed."));
    transaction.onabort = () => reject(transaction.error ?? new Error("Key storage aborted."));
    operation(transaction.objectStore(KEY_STORE));
  });
}

function isCryptoKeyPair(value: unknown): value is CryptoKeyPair {
  if (!isRecord(value)) return false;
  const privateKey = value.privateKey;
  const publicKey = value.publicKey;
  return (
    privateKey instanceof CryptoKey &&
    publicKey instanceof CryptoKey &&
    privateKey.type === "private" &&
    publicKey.type === "public" &&
    privateKey.algorithm.name === "ECDSA" &&
    publicKey.algorithm.name === "ECDSA"
  );
}

async function exportBrowserPublicKey(key: CryptoKey): Promise<BrowserPublicKeyJwk> {
  const exported = await crypto.subtle.exportKey("jwk", key);
  const parsed = parseBrowserPublicKeyJwk({
    kty: exported.kty,
    crv: exported.crv,
    x: exported.x,
    y: exported.y,
  });
  if (!parsed) throw new Error("Generated browser public key is invalid.");
  return parsed;
}

async function publicKeyFingerprint(publicKey: BrowserPublicKeyJwk): Promise<string> {
  const canonical = JSON.stringify({
    crv: publicKey.crv,
    kty: publicKey.kty,
    x: publicKey.x,
    y: publicKey.y,
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function getBrowserPairingCode(): Promise<string> {
  const stored = await chrome.storage.session.get(PAIRING_CODE_KEY);
  const current = stored[PAIRING_CODE_KEY];
  if (typeof current === "string" && /^[A-F0-9-]{49}$/.test(current)) return current;
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const compact = [...bytes]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  const pairingCode = compact.match(/.{1,4}/g)?.join("-") ?? compact;
  await chrome.storage.session.set({ [PAIRING_CODE_KEY]: pairingCode });
  return pairingCode;
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function isEmptyOrOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = new Set(allowed);
  return Object.keys(record).every((key) => keys.has(key));
}

async function broadcastState(): Promise<void> {
  const state = await popupState();
  await updateBadge({ pending: state.pending, ...(state.grant ? { grant: state.grant } : {}) });
  void chrome.runtime.sendMessage({ type: "state.changed", state }).catch(() => undefined);
}

async function updateBadge(state: StoredState): Promise<void> {
  if (state.grant) {
    await chrome.action.setBadgeBackgroundColor({ color: "#167c3a" });
    await chrome.action.setBadgeText({ text: "ON" });
  } else if (state.pending.length) {
    await chrome.action.setBadgeBackgroundColor({ color: "#a15c00" });
    await chrome.action.setBadgeText({ text: String(Math.min(state.pending.length, 9)) });
  } else {
    await chrome.action.setBadgeText({ text: "" });
  }
}

async function getBrowserInstanceId(): Promise<string> {
  const stored = await chrome.storage.local.get(BROWSER_INSTANCE_KEY);
  const existing = stored[BROWSER_INSTANCE_KEY];
  if (typeof existing === "string" && isUuid(existing)) return existing;
  const created = crypto.randomUUID();
  await chrome.storage.local.set({ [BROWSER_INSTANCE_KEY]: created });
  return created;
}

async function readState(): Promise<StoredState> {
  const result = await chrome.storage.session.get(STATE_KEY);
  const stored = result[STATE_KEY];
  if (!isRecord(stored) || !Array.isArray(stored.pending)) return { pending: [] };
  const pending = stored.pending.filter(isStoredPending).slice(0, 10);
  const grant = isStoredGrant(stored.grant) ? stored.grant : undefined;
  return { pending, ...(grant ? { grant } : {}) };
}

async function writeState(state: StoredState): Promise<void> {
  await chrome.storage.session.set({ [STATE_KEY]: state });
}

function leaseMatchesGrant(lease: BrowserExecute["lease"], grant: TabGrant): boolean {
  return (
    lease.leaseId === grant.leaseId &&
    lease.tabId === grant.tabId &&
    lease.documentId === grant.documentId &&
    lease.origin === grant.origin &&
    lease.expiresAt === grant.expiresAt &&
    sameScopes(lease.scopes, grant.scopes)
  );
}

function grantResultMatches(
  lease: TabGrant,
  request: PendingAccessRequest,
  tabId: number,
  documentId: string,
  origin: string,
): boolean {
  return (
    lease.requestId === request.requestId &&
    lease.tabId === tabId &&
    lease.documentId === documentId &&
    lease.origin === origin &&
    lease.expiresAt > Date.now() &&
    sameScopes(lease.scopes, request.scopes)
  );
}

function sameScopes(left: readonly TabGrantScope[], right: readonly TabGrantScope[]): boolean {
  return left.length === right.length && left.every((scope) => right.includes(scope));
}

function parseRevokedEvent(value: unknown): { leaseId: string; reason: string } | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ["leaseId", "reason"])) return undefined;
  if (
    !isUuid(value.leaseId) ||
    typeof value.reason !== "string" ||
    value.reason.length < 1 ||
    value.reason.length > 64
  )
    return undefined;
  return { leaseId: value.leaseId, reason: value.reason };
}

function isStoredPending(value: unknown): value is PendingAccessRequest {
  return (
    isRecord(value) &&
    isUuid(value.requestId) &&
    typeof value.clientId === "string" &&
    typeof value.taskId === "string" &&
    value.status === "pending" &&
    typeof value.expiresAt === "number" &&
    Array.isArray(value.scopes)
  );
}

function isStoredGrant(value: unknown): value is TabGrant {
  return (
    isRecord(value) &&
    isUuid(value.leaseId) &&
    isUuid(value.requestId) &&
    typeof value.tabId === "number" &&
    typeof value.documentId === "string" &&
    typeof value.origin === "string" &&
    typeof value.url === "string" &&
    typeof value.title === "string" &&
    typeof value.expiresAt === "number" &&
    Array.isArray(value.scopes)
  );
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(record).every((key) => allowedSet.has(key));
}

function isEmptyRecord(value: unknown): boolean {
  return isRecord(value) && Object.keys(value).length === 0;
}
