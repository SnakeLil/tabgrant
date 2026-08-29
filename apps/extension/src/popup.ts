import type { PendingAccessRequest, PopupState, TabGrant } from "./protocol.js";

const brokerStatus = requiredElement<HTMLSpanElement>("broker-status");
const grantSection = requiredElement<HTMLElement>("grant-section");
const pendingList = requiredElement<HTMLElement>("pending-list");
const errorElement = requiredElement<HTMLParagraphElement>("error");
const reconnectButton = requiredElement<HTMLButtonElement>("reconnect");
const pairingSection = requiredElement<HTMLElement>("pairing-section");
const pairingCode = requiredElement<HTMLElement>("pairing-code");
const pairingButton = requiredElement<HTMLButtonElement>("pair");

reconnectButton.addEventListener("click", () => void request({ type: "popup.reconnect" }));
pairingButton.addEventListener("click", () => void withBusy(pairingButton, { type: "popup.pair" }));
chrome.runtime.onMessage.addListener((message: unknown) => {
  if (isStateChanged(message)) render(message.state);
});
window.setInterval(() => void refresh(), 10_000);
void refresh();

async function refresh(): Promise<void> {
  await request({ type: "popup.get-state" });
}

async function request(message: unknown): Promise<void> {
  clearError();
  try {
    const response: { ok: true; state: PopupState } | { ok: false; error: string } =
      await chrome.runtime.sendMessage(message);
    if (!response.ok) throw new Error(response.error);
    render(response.state);
  } catch (error) {
    showError(error instanceof Error ? error.message : "The extension request failed.");
  }
}

function render(state: PopupState): void {
  brokerStatus.textContent = state.brokerKilled
    ? "Broker locked"
    : state.brokerConnected
      ? "Broker connected"
      : "Broker offline";
  brokerStatus.classList.toggle("connected", state.brokerConnected && !state.brokerKilled);
  pairingSection.hidden = state.browserPaired;
  pairingCode.textContent = state.pairingCode ?? "Waiting for broker…";
  renderGrant(state.grant);
  renderPending(state.pending, Boolean(state.grant));
}

function renderGrant(grant: TabGrant | undefined): void {
  grantSection.replaceChildren();
  if (!grant) return;

  const card = node("article", "card active");
  const heading = node("div", "row");
  const text = node("div");
  text.append(node("p", "title", "Access active"), node("p", "meta", grant.origin));
  const revoke = button("Revoke", "danger");
  revoke.addEventListener(
    "click",
    () => void withBusy(revoke, { type: "popup.revoke", leaseId: grant.leaseId }),
  );
  heading.append(text, revoke);
  card.append(heading, node("p", "meta", `Document ${grant.documentId}`), chips(grant.scopes));
  card.append(node("p", "meta", `Expires ${new Date(grant.expiresAt).toLocaleTimeString()}`));
  grantSection.append(card);
}

function renderPending(pending: PendingAccessRequest[], hasGrant: boolean): void {
  pendingList.replaceChildren();
  if (!pending.length) {
    pendingList.append(node("p", "empty", "No pending requests"));
    return;
  }
  for (const item of pending) {
    const card = node("article", "card");
    card.append(
      node("p", "title", item.clientId),
      node("p", "meta", `Task ${item.taskId}`),
      node("p", "reason", item.reason),
    );
    if (item.declaredModelProvider) {
      card.append(
        node("p", "meta", `Client-declared model provider: ${item.declaredModelProvider}`),
        node(
          "p",
          "warning",
          "TabGrant releases page data to this local client; it cannot enforce what the client does next.",
        ),
      );
    }
    card.append(chips(item.scopes));
    const grant = button(hasGrant ? "Replace grant with current tab" : "Grant current tab");
    grant.addEventListener(
      "click",
      () => void withBusy(grant, { type: "popup.grant-current-tab", requestId: item.requestId }),
    );
    card.append(grant);
    pendingList.append(card);
  }
}

async function withBusy(buttonElement: HTMLButtonElement, message: unknown): Promise<void> {
  buttonElement.disabled = true;
  await request(message);
  buttonElement.disabled = false;
}

function chips(values: readonly string[]): HTMLElement {
  const container = node("div", "chips");
  for (const value of values) container.append(node("span", "chip", value));
  return container;
}

function button(label: string, className = ""): HTMLButtonElement {
  const element = document.createElement("button");
  element.type = "button";
  element.className = className;
  element.textContent = label;
  return element;
}

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function showError(message: string): void {
  errorElement.textContent = message;
  errorElement.hidden = false;
}

function clearError(): void {
  errorElement.textContent = "";
  errorElement.hidden = true;
}

function requiredElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing popup element: ${id}`);
  return element as T;
}

function isStateChanged(value: unknown): value is { type: "state.changed"; state: PopupState } {
  return Boolean(
    value &&
    typeof value === "object" &&
    (value as Record<string, unknown>).type === "state.changed" &&
    typeof (value as Record<string, unknown>).state === "object",
  );
}
