import { describe, expect, it } from "vitest";
import { brokerStatusPresentation } from "./popup-status.js";

describe("brokerStatusPresentation", () => {
  it("reports a paired broker connection", () => {
    expect(
      brokerStatusPresentation({
        brokerConnected: true,
        brokerKilled: false,
        browserPaired: true,
        nativeRelayConnected: true,
      }),
    ).toEqual({ text: "Broker connected", tone: "connected" });
  });

  it("distinguishes a reachable native relay awaiting pairing", () => {
    expect(
      brokerStatusPresentation({
        brokerConnected: false,
        brokerKilled: false,
        browserPaired: false,
        nativeRelayConnected: true,
      }),
    ).toEqual({ text: "Pairing required", tone: "reachable" });
  });

  it("distinguishes paired browser reauthentication from initial pairing", () => {
    expect(
      brokerStatusPresentation({
        brokerConnected: false,
        brokerKilled: false,
        browserPaired: true,
        nativeRelayConnected: true,
      }),
    ).toEqual({ text: "Broker connecting", tone: "reachable" });
  });

  it("reports an unavailable native relay as offline", () => {
    expect(
      brokerStatusPresentation({
        brokerConnected: false,
        brokerKilled: false,
        browserPaired: true,
        nativeRelayConnected: false,
      }),
    ).toEqual({ text: "Broker offline", tone: "offline" });
  });

  it("gives the kill switch precedence over connection state", () => {
    expect(
      brokerStatusPresentation({
        brokerConnected: true,
        brokerKilled: true,
        browserPaired: true,
        nativeRelayConnected: true,
      }),
    ).toEqual({ text: "Broker locked", tone: "locked" });
  });
});
