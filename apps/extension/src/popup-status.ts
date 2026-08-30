import type { PopupState } from "./protocol.js";

export type BrokerStatusTone = "connected" | "reachable" | "offline" | "locked";

export interface BrokerStatusPresentation {
  text: string;
  tone: BrokerStatusTone;
}

export function brokerStatusPresentation(
  state: Pick<
    PopupState,
    "brokerConnected" | "brokerKilled" | "browserPaired" | "nativeRelayConnected"
  >,
): BrokerStatusPresentation {
  if (state.brokerKilled) return { text: "Broker locked", tone: "locked" };
  if (state.brokerConnected) return { text: "Broker connected", tone: "connected" };
  if (state.nativeRelayConnected) {
    return state.browserPaired
      ? { text: "Broker connecting", tone: "reachable" }
      : { text: "Pairing required", tone: "reachable" };
  }
  return { text: "Broker offline", tone: "offline" };
}
