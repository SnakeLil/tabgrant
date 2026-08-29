import { randomUUID } from "node:crypto";
import { connect, type Socket } from "node:net";
import { createAuthHello, readBrokerSecret } from "./auth.js";
import type { RuntimePaths } from "./paths.js";
import { getRuntimePaths } from "./paths.js";
import { RpcPeer } from "./wire.js";

export interface BrokerClientIdentity {
  readonly clientId: string;
  readonly taskId: string;
  readonly instanceId?: string;
}

export interface BrokerClient {
  readonly peer: RpcPeer;
  readonly socket: Socket;
}

export async function connectBroker(
  identity: BrokerClientIdentity,
  paths: RuntimePaths = getRuntimePaths(),
  onRequest: (method: string, params: unknown) => Promise<unknown> = () =>
    Promise.reject(new Error("This broker client does not accept incoming requests.")),
  onEvent: (event: string, payload: unknown) => void = () => undefined,
): Promise<BrokerClient> {
  const socket = await connectSocket(paths.socketPath);
  const peer = new RpcPeer(socket, onRequest, onEvent);
  const secret = await readBrokerSecret(paths.secretPath);
  const hello = createAuthHello(secret, {
    role: "agent",
    clientId: identity.clientId,
    taskId: identity.taskId,
    instanceId: identity.instanceId ?? randomUUID(),
  });
  await peer.request("session.hello", hello, 5_000);
  return { peer, socket };
}

function connectSocket(path: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    const onError = (error: Error): void => reject(error);
    socket.once("error", onError);
    socket.once("connect", () => {
      socket.off("error", onError);
      resolve(socket);
    });
  });
}
