export const WIRE_VERSION = 1 as const;

export const TAB_GRANT_SCOPES = [
  "tab.metadata.read",
  "page.a11y.read",
  "page.element.inspect",
  "page.scroll",
  "page.highlight",
  "page.navigate.same_origin",
  "data.egress.model",
] as const;

export type TabGrantScope = (typeof TAB_GRANT_SCOPES)[number];

export interface WireRequest {
  v: 1;
  kind: "request";
  id: string;
  method: string;
  params: unknown;
}

export interface WireResponse {
  v: 1;
  kind: "response";
  id: string;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
}

export interface WireEvent {
  v: 1;
  kind: "event";
  event: string;
  payload: unknown;
}

export type WireEnvelope = WireRequest | WireResponse | WireEvent;

export interface PendingAccessRequest {
  requestId: string;
  clientId: string;
  taskId: string;
  scopes: TabGrantScope[];
  reason: string;
  status: "pending";
  expiresAt: number;
  declaredModelProvider?: string;
}

export interface TabGrant {
  leaseId: string;
  requestId: string;
  tabId: number;
  documentId: string;
  origin: string;
  url: string;
  title: string;
  scopes: TabGrantScope[];
  expiresAt: number;
}

export interface BrowserExecuteLease {
  leaseId: string;
  tabId: number;
  documentId: string;
  origin: string;
  scopes: TabGrantScope[];
  expiresAt: number;
}

export interface BrowserPublicKeyJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

export type BrowserAuthChallengeResponse =
  | { paired: false }
  | {
      paired: true;
      challengeId: string;
      challenge: string;
      expiresAt: number;
    };

export type BrowserExecute =
  | { command: "snapshot"; lease: BrowserExecuteLease; args: { maxNodes: number } }
  | { command: "highlight"; lease: BrowserExecuteLease; args: { ref: string; epoch: number } }
  | { command: "scroll"; lease: BrowserExecuteLease; args: { deltaY: number } }
  | { command: "navigate"; lease: BrowserExecuteLease; args: { url: string } };

export type PopupRequest =
  | { type: "popup.get-state" }
  | { type: "popup.pair" }
  | { type: "popup.grant-current-tab"; requestId: string }
  | { type: "popup.revoke"; leaseId: string }
  | { type: "popup.reconnect" };

export interface PopupState {
  nativeRelayConnected: boolean;
  brokerConnected: boolean;
  brokerKilled: boolean;
  browserPaired: boolean;
  pairingCode?: string;
  pending: PendingAccessRequest[];
  grant?: TabGrant;
}

export function parseBrowserPublicKeyJwk(value: unknown): BrowserPublicKeyJwk | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ["kty", "crv", "x", "y"])) return undefined;
  if (
    value.kty !== "EC" ||
    value.crv !== "P-256" ||
    typeof value.x !== "string" ||
    typeof value.y !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.x) ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.y)
  )
    return undefined;
  return { kty: "EC", crv: "P-256", x: value.x, y: value.y };
}

export function parseBrowserAuthChallenge(
  value: unknown,
  now = Date.now(),
): BrowserAuthChallengeResponse | undefined {
  if (!isRecord(value) || typeof value.paired !== "boolean") return undefined;
  if (value.paired === false) {
    return hasOnlyKeys(value, ["paired"]) ? { paired: false } : undefined;
  }
  if (!hasOnlyKeys(value, ["paired", "challengeId", "challenge", "expiresAt"])) return undefined;
  if (
    !isUuid(value.challengeId) ||
    typeof value.challenge !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.challenge) ||
    typeof value.expiresAt !== "number" ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= now ||
    value.expiresAt > now + 31_000
  )
    return undefined;
  return {
    paired: true,
    challengeId: value.challengeId,
    challenge: value.challenge,
    expiresAt: value.expiresAt,
  };
}

export function createWireRequest(
  method: string,
  params: unknown,
  id = crypto.randomUUID(),
): WireRequest {
  if (!isUuid(id) || !isMethod(method)) throw new Error("Invalid wire request metadata.");
  return { v: WIRE_VERSION, kind: "request", id, method, params };
}

export function createWireResponse(id: string, result: unknown): WireResponse {
  return { v: WIRE_VERSION, kind: "response", id, ok: true, result };
}

export function createWireError(id: string, code: string, message: string): WireResponse {
  const safeCode = /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "EXTENSION_ERROR";
  const safeMessage = message.trim().slice(0, 512) || "Extension request failed.";
  return {
    v: WIRE_VERSION,
    kind: "response",
    id,
    ok: false,
    error: { code: safeCode, message: safeMessage },
  };
}

export function parseWireEnvelope(value: unknown): WireEnvelope | undefined {
  if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.kind !== "string")
    return undefined;
  if (value.kind === "request") {
    if (!hasOnlyKeys(value, ["v", "kind", "id", "method", "params"])) return undefined;
    if (!isUuid(value.id) || !isMethod(value.method) || !("params" in value)) return undefined;
    return { v: 1, kind: "request", id: value.id, method: value.method, params: value.params };
  }
  if (value.kind === "response") {
    if (!hasOnlyKeys(value, ["v", "kind", "id", "ok", "result", "error"])) return undefined;
    if (!isUuid(value.id) || typeof value.ok !== "boolean") return undefined;
    if (value.ok) {
      if (value.error !== undefined) return undefined;
      return {
        v: 1,
        kind: "response",
        id: value.id,
        ok: true,
        ...("result" in value ? { result: value.result } : {}),
      };
    }
    const error = parseWireError(value.error);
    if (!error || value.result !== undefined) return undefined;
    return { v: 1, kind: "response", id: value.id, ok: false, error };
  }
  if (value.kind === "event") {
    if (!hasOnlyKeys(value, ["v", "kind", "event", "payload"])) return undefined;
    if (!isMethod(value.event) || !("payload" in value)) return undefined;
    return { v: 1, kind: "event", event: value.event, payload: value.payload };
  }
  return undefined;
}

export function parsePendingAccessRequest(
  value: unknown,
  now = Date.now(),
): PendingAccessRequest | undefined {
  if (!isRecord(value)) return undefined;
  const allowedKeys = [
    "requestId",
    "clientId",
    "taskId",
    "scopes",
    "reason",
    "status",
    "expiresAt",
    "declaredModelProvider",
    "leaseId",
  ];
  if (!hasOnlyKeys(value, allowedKeys) || value.status !== "pending") return undefined;
  const requestId = uuid(value.requestId);
  const clientId = boundedString(value.clientId, 128);
  const taskId = boundedString(value.taskId, 128);
  const scopes = parseScopes(value.scopes);
  const reason = boundedString(value.reason, 240);
  const expiresAt = parseIsoTimestamp(value.expiresAt);
  const declaredModelProvider =
    value.declaredModelProvider === undefined
      ? undefined
      : boundedString(value.declaredModelProvider, 128);
  if (!requestId || !clientId || !taskId || !scopes || !reason || !expiresAt || expiresAt <= now)
    return undefined;
  if (value.declaredModelProvider !== undefined && !declaredModelProvider) return undefined;
  if (scopes.includes("data.egress.model") && !declaredModelProvider) return undefined;
  return {
    requestId,
    clientId,
    taskId,
    scopes,
    reason,
    status: "pending",
    expiresAt,
    ...(declaredModelProvider ? { declaredModelProvider } : {}),
  };
}

export function parsePendingList(
  value: unknown,
  now = Date.now(),
): PendingAccessRequest[] | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ["requests"]) || !Array.isArray(value.requests))
    return undefined;
  if (value.requests.length > 100) return undefined;
  const pending: PendingAccessRequest[] = [];
  for (const item of value.requests) {
    if (isRecord(item) && item.status !== "pending") continue;
    const parsed = parsePendingAccessRequest(item, now);
    if (!parsed) return undefined;
    pending.push(parsed);
  }
  return pending.slice(0, 10);
}

export function parseGrantedLease(value: unknown): TabGrant | undefined {
  if (!isRecord(value)) return undefined;
  const allowedKeys = [
    "leaseId",
    "requestId",
    "tabId",
    "documentId",
    "origin",
    "url",
    "title",
    "scopes",
    "declaredModelProvider",
    "issuedAt",
    "expiresAt",
    "active",
    "remainingUses",
    "remainingEgressBytes",
    "inFlight",
    "revokeReason",
  ];
  if (!hasOnlyKeys(value, allowedKeys) || value.active !== true) return undefined;
  const leaseId = uuid(value.leaseId);
  const requestId = uuid(value.requestId);
  const tabId = finiteInteger(value.tabId, 0, Number.MAX_SAFE_INTEGER);
  const documentId = boundedString(value.documentId, 128);
  const origin = safeOrigin(value.origin);
  const url = boundedString(value.url, 2_048);
  const title =
    typeof value.title === "string" && value.title.length <= 256 ? value.title : undefined;
  const scopes = parseScopes(value.scopes);
  const issuedAt = parseIsoTimestamp(value.issuedAt);
  const expiresAt = parseIsoTimestamp(value.expiresAt);
  const remainingUses = finiteInteger(value.remainingUses, 0, Number.MAX_SAFE_INTEGER);
  const remainingEgressBytes = finiteInteger(
    value.remainingEgressBytes,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const inFlight = finiteInteger(value.inFlight, 0, Number.MAX_SAFE_INTEGER);
  const declaredModelProvider =
    value.declaredModelProvider === undefined
      ? undefined
      : boundedString(value.declaredModelProvider, 128);
  const revokeReason =
    value.revokeReason === undefined ? undefined : boundedString(value.revokeReason, 64);
  if (
    !leaseId ||
    !requestId ||
    tabId === undefined ||
    !documentId ||
    !origin ||
    !url ||
    title === undefined ||
    !scopes ||
    !issuedAt ||
    !expiresAt ||
    issuedAt > expiresAt ||
    remainingUses === undefined ||
    remainingEgressBytes === undefined ||
    inFlight === undefined ||
    (value.declaredModelProvider !== undefined && !declaredModelProvider) ||
    (value.revokeReason !== undefined && !revokeReason)
  )
    return undefined;
  return { leaseId, requestId, tabId, documentId, origin, url, title, scopes, expiresAt };
}

export function parseBrowserExecute(value: unknown): BrowserExecute | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ["command", "lease", "args"])) return undefined;
  const lease = parseExecuteLease(value.lease);
  if (!lease || !isRecord(value.args) || typeof value.command !== "string") return undefined;
  if (value.command === "snapshot") {
    if (!hasOnlyKeys(value.args, ["maxNodes"])) return undefined;
    const maxNodes = finiteInteger(value.args.maxNodes, 1, 500);
    return maxNodes === undefined ? undefined : { command: "snapshot", lease, args: { maxNodes } };
  }
  if (value.command === "highlight") {
    if (!hasOnlyKeys(value.args, ["ref", "epoch"])) return undefined;
    const ref = boundedString(value.args.ref, 64);
    const epoch = finiteInteger(value.args.epoch, 0, Number.MAX_SAFE_INTEGER);
    return !ref || epoch === undefined
      ? undefined
      : { command: "highlight", lease, args: { ref, epoch } };
  }
  if (value.command === "scroll") {
    if (!hasOnlyKeys(value.args, ["deltaY"])) return undefined;
    const deltaY = finiteInteger(value.args.deltaY, -2_000, 2_000);
    return deltaY === undefined ? undefined : { command: "scroll", lease, args: { deltaY } };
  }
  if (value.command === "navigate") {
    if (!hasOnlyKeys(value.args, ["url"])) return undefined;
    const url = boundedString(value.args.url, 2_048);
    return !url ? undefined : { command: "navigate", lease, args: { url } };
  }
  return undefined;
}

export function parsePopupRequest(value: unknown): PopupRequest | undefined {
  if (!isRecord(value) || typeof value.type !== "string") return undefined;
  if (value.type === "popup.get-state" || value.type === "popup.reconnect") {
    return hasOnlyKeys(value, ["type"]) ? { type: value.type } : undefined;
  }
  if (value.type === "popup.pair") {
    return hasOnlyKeys(value, ["type"]) ? { type: "popup.pair" } : undefined;
  }
  if (value.type === "popup.grant-current-tab" && hasOnlyKeys(value, ["type", "requestId"])) {
    const requestId = uuid(value.requestId);
    return requestId ? { type: value.type, requestId } : undefined;
  }
  if (value.type === "popup.revoke" && hasOnlyKeys(value, ["type", "leaseId"])) {
    const leaseId = uuid(value.leaseId);
    return leaseId ? { type: value.type, leaseId } : undefined;
  }
  return undefined;
}

function parseExecuteLease(value: unknown): BrowserExecuteLease | undefined {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["leaseId", "tabId", "documentId", "origin", "scopes", "expiresAt"])
  )
    return undefined;
  const leaseId = uuid(value.leaseId);
  const tabId = finiteInteger(value.tabId, 0, Number.MAX_SAFE_INTEGER);
  const documentId = boundedString(value.documentId, 128);
  const origin = safeOrigin(value.origin);
  const scopes = parseScopes(value.scopes);
  const expiresAt = finiteInteger(value.expiresAt, 1, Number.MAX_SAFE_INTEGER);
  if (
    !leaseId ||
    tabId === undefined ||
    !documentId ||
    !origin ||
    !scopes ||
    expiresAt === undefined
  )
    return undefined;
  return { leaseId, tabId, documentId, origin, scopes, expiresAt };
}

function parseScopes(value: unknown): TabGrantScope[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > TAB_GRANT_SCOPES.length)
    return undefined;
  const scopes = new Set<TabGrantScope>();
  for (const item of value) {
    if (typeof item !== "string" || !TAB_GRANT_SCOPES.includes(item as TabGrantScope))
      return undefined;
    scopes.add(item as TabGrantScope);
  }
  if (scopes.size !== value.length) return undefined;
  return [...scopes];
}

function parseWireError(value: unknown): { code: string; message: string } | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ["code", "message"])) return undefined;
  if (typeof value.code !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(value.code))
    return undefined;
  const message = boundedString(value.message, 512);
  return message ? { code: value.code, message } : undefined;
}

function parseIsoTimestamp(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function safeOrigin(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const url = new URL(value);
    return url.origin === value ? value : undefined;
  } catch {
    return undefined;
  }
}

function uuid(value: unknown): string | undefined {
  return typeof value === "string" && isUuid(value) ? value : undefined;
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function isMethod(value: unknown): value is string {
  return typeof value === "string" && value.length <= 96 && /^[a-z][a-z0-9._-]+$/.test(value);
}

function boundedString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= maxLength ? normalized : undefined;
}

function finiteInteger(value: unknown, minimum: number, maximum: number): number | undefined {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(record).every((key) => allowedSet.has(key));
}
