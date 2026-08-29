import { isSensitiveControl } from "./security.js";

const BRIDGE_KEY = "__tabGrantV01__";
const HIGHLIGHT_ATTRIBUTE = "data-tabgrant-highlight";

interface SnapshotNode {
  ref: string;
  tag: string;
  role: string;
  name: string;
  disabled: boolean;
  sensitive: boolean;
}

type BridgeAction =
  | { type: "bridge.identify" }
  | { type: "snapshot"; maxNodes: number }
  | { type: "highlight"; ref: string; epoch: number }
  | { type: "scroll"; deltaY: number }
  | { type: "bridge.teardown" };

interface BridgeCommand {
  type: "bridge.command";
  requestId: string;
  expectedDocumentId?: string;
  action: BridgeAction;
}

interface BridgeState {
  enabled: boolean;
  readonly documentId: string;
  epoch: number;
  refs: Map<string, Element>;
  listener: (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ) => boolean | undefined;
}

declare global {
  interface Window {
    __tabGrantV01__?: BridgeState;
  }
}

const previous = window[BRIDGE_KEY];
if (previous) {
  previous.enabled = true;
} else {
  const state: BridgeState = {
    enabled: true,
    documentId: crypto.randomUUID(),
    epoch: 0,
    refs: new Map(),
    listener: (message, _sender, sendResponse) => {
      const command = parseBridgeCommand(message);
      if (!command) return undefined;
      if (!state.enabled) {
        sendResponse(
          failure(command.requestId, "BRIDGE_REVOKED", "This document grant has been revoked."),
        );
        return false;
      }
      if (
        command.action.type !== "bridge.identify" &&
        command.expectedDocumentId !== state.documentId
      ) {
        sendResponse(
          failure(
            command.requestId,
            "DOCUMENT_CHANGED",
            "The command is not bound to this document.",
          ),
        );
        return false;
      }
      try {
        sendResponse(success(command.requestId, executeAction(state, command.action)));
      } catch (error) {
        const message = error instanceof Error ? error.message : "The browser action failed.";
        const code = message.startsWith("STALE_EPOCH") ? "STALE_EPOCH" : "ACTION_FAILED";
        sendResponse(failure(command.requestId, code, message));
      }
      return false;
    },
  };
  window[BRIDGE_KEY] = state;
  chrome.runtime.onMessage.addListener(state.listener);
}

function executeAction(state: BridgeState, action: BridgeAction): unknown {
  switch (action.type) {
    case "bridge.identify":
      return { documentId: state.documentId };
    case "snapshot":
      return snapshot(state, action.maxNodes);
    case "highlight":
      return highlight(state, action.epoch, action.ref);
    case "scroll":
      return scroll(action.deltaY);
    case "bridge.teardown":
      teardown(state);
      return { revoked: true };
    default:
      return assertNever(action);
  }
}

function snapshot(state: BridgeState, maxNodes: number) {
  const selector =
    'a[href],button,input:not([type="hidden"]),select,textarea,[role],[contenteditable="true"],[tabindex],h1,h2,h3,h4,h5,h6,p,li';
  const allCandidates = [...document.querySelectorAll(selector)].filter(isVisible);
  const candidates = allCandidates.slice(0, maxNodes);
  state.epoch += 1;
  state.refs.clear();

  const nodes: SnapshotNode[] = candidates.map((element, index) => {
    const ref = `tg-${index + 1}`;
    state.refs.set(ref, element);
    return {
      ref,
      tag: element.tagName.toLowerCase(),
      role: roleFor(element),
      name: accessibleName(element),
      disabled: isDisabled(element),
      sensitive: isSensitiveControl(element),
    };
  });

  return {
    documentId: state.documentId,
    epoch: state.epoch,
    nodes,
    truncated: allCandidates.length > candidates.length,
  };
}

function highlight(state: BridgeState, epoch: number, ref: string) {
  const element = resolveRef(state, epoch, ref);
  const rect = element.getBoundingClientRect();
  const overlay = document.createElement("div");
  overlay.setAttribute(HIGHLIGHT_ATTRIBUTE, "true");
  Object.assign(overlay.style, {
    position: "fixed",
    pointerEvents: "none",
    zIndex: "2147483647",
    left: `${Math.max(0, rect.left - 3)}px`,
    top: `${Math.max(0, rect.top - 3)}px`,
    width: `${Math.max(0, rect.width + 6)}px`,
    height: `${Math.max(0, rect.height + 6)}px`,
    border: "3px solid #0a84ff",
    borderRadius: "8px",
    boxShadow: "0 0 0 2px rgba(255,255,255,.9), 0 8px 30px rgba(0,0,0,.24)",
  });
  document.documentElement.append(overlay);
  window.setTimeout(() => overlay.remove(), 1_500);
  return { highlighted: ref, epoch };
}

function scroll(deltaY: number) {
  window.scrollBy({ top: deltaY, behavior: "smooth" });
  return { deltaY };
}

function teardown(state: BridgeState): void {
  state.enabled = false;
  state.refs.clear();
  document.querySelectorAll(`[${HIGHLIGHT_ATTRIBUTE}]`).forEach((element) => element.remove());
  chrome.runtime.onMessage.removeListener(state.listener);
  delete window[BRIDGE_KEY];
}

function resolveRef(state: BridgeState, epoch: number, ref: string): Element {
  if (state.epoch === 0 || state.epoch !== epoch)
    throw new Error("STALE_EPOCH: take a new snapshot.");
  const element = state.refs.get(ref);
  if (!element || !element.isConnected)
    throw new Error("STALE_EPOCH: the element is no longer available.");
  return element;
}

function parseBridgeCommand(value: unknown): BridgeCommand | undefined {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["type", "requestId", "expectedDocumentId", "action"])
  )
    return undefined;
  const requestId = boundedString(value.requestId, 128);
  if (value.type !== "bridge.command" || !requestId || !isRecord(value.action)) return undefined;
  const expectedDocumentId =
    value.expectedDocumentId === undefined
      ? undefined
      : boundedString(value.expectedDocumentId, 128);
  if (value.expectedDocumentId !== undefined && !expectedDocumentId) return undefined;

  const action = value.action;
  if (action.type === "bridge.identify" && hasOnlyKeys(action, ["type"])) {
    return { type: "bridge.command", requestId, action: { type: "bridge.identify" } };
  }
  if (action.type === "bridge.teardown" && hasOnlyKeys(action, ["type"]) && expectedDocumentId) {
    return {
      type: "bridge.command",
      requestId,
      expectedDocumentId,
      action: { type: "bridge.teardown" },
    };
  }
  if (
    action.type === "snapshot" &&
    hasOnlyKeys(action, ["type", "maxNodes"]) &&
    expectedDocumentId
  ) {
    const maxNodes = finiteInteger(action.maxNodes, 1, 500);
    return maxNodes === undefined
      ? undefined
      : {
          type: "bridge.command",
          requestId,
          expectedDocumentId,
          action: { type: "snapshot", maxNodes },
        };
  }
  if (
    action.type === "highlight" &&
    hasOnlyKeys(action, ["type", "ref", "epoch"]) &&
    expectedDocumentId
  ) {
    const ref = boundedString(action.ref, 64);
    const epoch = finiteInteger(action.epoch, 0, Number.MAX_SAFE_INTEGER);
    return !ref || epoch === undefined
      ? undefined
      : {
          type: "bridge.command",
          requestId,
          expectedDocumentId,
          action: { type: "highlight", ref, epoch },
        };
  }
  if (action.type === "scroll" && hasOnlyKeys(action, ["type", "deltaY"]) && expectedDocumentId) {
    const deltaY = finiteInteger(action.deltaY, -2_000, 2_000);
    return deltaY === undefined
      ? undefined
      : {
          type: "bridge.command",
          requestId,
          expectedDocumentId,
          action: { type: "scroll", deltaY },
        };
  }
  return undefined;
}

function accessibleName(element: Element): string {
  const labelledBy = element.getAttribute("aria-labelledby");
  const labelledText = labelledBy
    ?.split(/\s+/)
    .map((id) => document.getElementById(id)?.textContent?.trim() ?? "")
    .filter(Boolean)
    .join(" ");
  const candidate =
    element.getAttribute("aria-label") ??
    labelledText ??
    element.getAttribute("alt") ??
    element.getAttribute("title") ??
    element.getAttribute("placeholder") ??
    element.textContent ??
    "";
  return candidate.replace(/\s+/g, " ").trim().slice(0, 200);
}

function roleFor(element: Element): string {
  const explicit = element.getAttribute("role");
  if (explicit) return explicit;
  const tag = element.tagName.toLowerCase();
  if (tag === "a") return "link";
  if (tag === "button") return "button";
  if (tag === "select") return "combobox";
  if (tag === "textarea") return "textbox";
  if (tag === "input") {
    const type = (element as HTMLInputElement).type;
    if (type === "checkbox") return "checkbox";
    if (type === "radio") return "radio";
    if (type === "submit" || type === "button") return "button";
    return "textbox";
  }
  return tag;
}

function isVisible(element: Element): boolean {
  const rect = element.getBoundingClientRect();
  const style = getComputedStyle(element);
  return (
    rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none"
  );
}

function isDisabled(element: Element): boolean {
  return (
    element.getAttribute("aria-disabled") === "true" ||
    ("disabled" in element && Boolean((element as HTMLButtonElement | HTMLInputElement).disabled))
  );
}

function success(requestId: string, result: unknown) {
  return { ok: true, requestId, result };
}

function failure(requestId: string, code: string, message: string) {
  return { ok: false, requestId, error: { code, message } };
}

function boundedString(value: unknown, maxLength: number): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength
    ? value
    : undefined;
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

function assertNever(value: never): never {
  throw new Error(`Unsupported browser action: ${JSON.stringify(value)}`);
}
