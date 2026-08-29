import { randomUUID } from "node:crypto";
import { connectBrokerWithAutostart } from "./autostart.js";
import type { connectBroker } from "./client.js";
import { NativeMessageTransport } from "./native-framing.js";
import {
  BrokerRpcError,
  WireEnvelopeSchema,
  type ResponseEnvelope,
  type WireEnvelope,
} from "./wire.js";
import { WIRE_VERSION } from "./constants.js";

interface PendingExtensionRequest {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

// The production approver has a 60 second hard process timeout. Keep transport
// headroom so an approved challenge is not discarded at the same deadline.
const PAIRING_RPC_TIMEOUT_MS = 70_000;

export async function runNativeHost(): Promise<void> {
  const pending = new Map<string, PendingExtensionRequest>();
  const queued: WireEnvelope[] = [];
  const transportHolder: { current?: NativeMessageTransport } = {};
  const sendToExtension = (envelope: WireEnvelope): void => {
    if (transportHolder.current !== undefined) {
      transportHolder.current.send(envelope);
      return;
    }
    if (queued.length >= 32) {
      throw new BrokerRpcError("RATE_LIMITED", "Native host startup queue is full.");
    }
    queued.push(envelope);
  };
  const broker = await connectBrokerWithAutostart(
    {
      // Native Messaging is only a relay. This connection starts with agent authority and the
      // broker upgrades it only after the extension proves its paired, non-exportable key.
      clientId: "tabgrant-native-relay",
      taskId: "native-relay",
    },
    undefined,
    async (method, params) => {
      const id = randomUUID();
      const result = new Promise<unknown>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new BrokerRpcError("BROWSER_TIMEOUT", `Extension timed out handling ${method}.`));
        }, 15_000);
        timer.unref();
        pending.set(id, { resolve, reject, timer });
      });
      sendToExtension({ v: WIRE_VERSION, kind: "request", id, method, params });
      return result;
    },
    (event, payload) => sendToExtension({ v: WIRE_VERSION, kind: "event", event, payload }),
  );

  const transport = new NativeMessageTransport(
    process.stdin,
    process.stdout,
    (message) => {
      void handleExtensionMessage(message, broker.peer, pending, transport);
    },
    (error) => {
      process.stderr.write(`TabGrant native host input error: ${error.message}\n`);
      broker.socket.destroy();
      process.exitCode = 1;
    },
  );
  transportHolder.current = transport;
  for (const envelope of queued.splice(0)) transport.send(envelope);

  broker.socket.once("close", () => process.exit(0));
}

async function handleExtensionMessage(
  message: unknown,
  brokerPeer: Awaited<ReturnType<typeof connectBroker>>["peer"],
  pending: Map<string, PendingExtensionRequest>,
  transport: NativeMessageTransport,
): Promise<void> {
  let envelope;
  try {
    envelope = WireEnvelopeSchema.parse(message);
  } catch {
    process.stderr.write("TabGrant native host rejected a malformed extension message.\n");
    return;
  }

  if (envelope.kind === "response") {
    settleExtensionResponse(envelope, pending);
    return;
  }
  if (envelope.kind === "event") {
    brokerPeer.sendEvent(envelope.event, envelope.payload);
    return;
  }

  try {
    const result = await brokerPeer.request(
      envelope.method,
      envelope.params,
      envelope.method === "browser.auth.pair" ? PAIRING_RPC_TIMEOUT_MS : 15_000,
    );
    transport.send({ v: WIRE_VERSION, kind: "response", id: envelope.id, ok: true, result });
  } catch (error) {
    const rpcError =
      error instanceof BrokerRpcError
        ? error
        : new BrokerRpcError("BROKER_ERROR", "Broker request failed.");
    transport.send({
      v: WIRE_VERSION,
      kind: "response",
      id: envelope.id,
      ok: false,
      error: { code: rpcError.code, message: rpcError.message },
    });
  }
}

function settleExtensionResponse(
  envelope: ResponseEnvelope,
  pending: Map<string, PendingExtensionRequest>,
): void {
  const request = pending.get(envelope.id);
  if (request === undefined) {
    return;
  }
  clearTimeout(request.timer);
  pending.delete(envelope.id);
  if (envelope.ok) {
    request.resolve(envelope.result);
  } else {
    request.reject(
      new BrokerRpcError(
        envelope.error?.code ?? "BROWSER_ERROR",
        envelope.error?.message ?? "Extension request failed.",
      ),
    );
  }
}
