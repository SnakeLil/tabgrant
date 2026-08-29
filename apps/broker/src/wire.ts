import { randomUUID } from "node:crypto";
import type { Socket } from "node:net";
import { performance } from "node:perf_hooks";
import { z } from "zod";
import { MAX_MESSAGE_BYTES, WIRE_VERSION } from "./constants.js";

export const INBOUND_REQUEST_WINDOW_MS = 60_000;
export const MAX_INBOUND_REQUESTS_PER_WINDOW = 240;

const RequestEnvelopeSchema = z
  .object({
    v: z.literal(WIRE_VERSION),
    kind: z.literal("request"),
    id: z.string().uuid(),
    method: z
      .string()
      .min(1)
      .max(96)
      .regex(/^[a-z][a-z0-9._-]+$/),
    params: z.unknown(),
  })
  .strict();

const ResponseEnvelopeSchema = z
  .object({
    v: z.literal(WIRE_VERSION),
    kind: z.literal("response"),
    id: z.string().uuid(),
    ok: z.boolean(),
    result: z.unknown().optional(),
    error: z
      .object({
        code: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[A-Z][A-Z0-9_]+$/),
        message: z.string().min(1).max(512),
      })
      .strict()
      .optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.ok && value.error !== undefined) {
      context.addIssue({
        code: "custom",
        message: "Successful responses cannot include an error.",
      });
    }
    if (!value.ok && value.error === undefined) {
      context.addIssue({ code: "custom", message: "Failed responses must include an error." });
    }
  });

const EventEnvelopeSchema = z
  .object({
    v: z.literal(WIRE_VERSION),
    kind: z.literal("event"),
    event: z
      .string()
      .min(1)
      .max(96)
      .regex(/^[a-z][a-z0-9._-]+$/),
    payload: z.unknown(),
  })
  .strict();

export const WireEnvelopeSchema = z.discriminatedUnion("kind", [
  RequestEnvelopeSchema,
  ResponseEnvelopeSchema,
  EventEnvelopeSchema,
]);

export type RequestEnvelope = z.infer<typeof RequestEnvelopeSchema>;
export type ResponseEnvelope = z.infer<typeof ResponseEnvelopeSchema>;
export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;
export type WireEnvelope = z.infer<typeof WireEnvelopeSchema>;

export class BrokerRpcError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "BrokerRpcError";
  }
}

export class JsonLineDecoder {
  private buffer = Buffer.alloc(0);

  public push(chunk: Buffer): unknown[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages: unknown[] = [];
    let newline = this.buffer.indexOf(0x0a);
    while (newline !== -1) {
      const line = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      if (line.byteLength > MAX_MESSAGE_BYTES) {
        throw new BrokerRpcError("MESSAGE_TOO_LARGE", "IPC message exceeded the 1 MiB limit.");
      }
      if (line.byteLength > 0) {
        messages.push(JSON.parse(line.toString("utf8")) as unknown);
      }
      newline = this.buffer.indexOf(0x0a);
    }
    if (this.buffer.byteLength > MAX_MESSAGE_BYTES) {
      throw new BrokerRpcError("MESSAGE_TOO_LARGE", "IPC message exceeded the 1 MiB limit.");
    }
    return messages;
  }
}

interface PendingRequest {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

export type RequestHandler = (method: string, params: unknown) => Promise<unknown>;
export type EventHandler = (event: string, payload: unknown) => void;

export class RpcPeer {
  private readonly decoder = new JsonLineDecoder();
  private readonly pending = new Map<string, PendingRequest>();
  private closed = false;
  private inboundRequests = 0;
  private inboundWindowStartedAt: number | undefined;
  private inboundRequestsInWindow = 0;

  public constructor(
    private readonly socket: Socket,
    private readonly onRequest: RequestHandler,
    private readonly onEvent: EventHandler = () => undefined,
    private readonly now: () => number = () => performance.now(),
  ) {
    socket.on("data", (chunk: Buffer) => {
      try {
        for (const value of this.decoder.push(chunk)) {
          void this.receive(value).catch((error: unknown) => {
            this.destroy(error instanceof Error ? error : new Error(String(error)));
          });
        }
      } catch (error) {
        this.destroy(error instanceof Error ? error : new Error(String(error)));
      }
    });
    socket.once("close", () =>
      this.destroy(new BrokerRpcError("BROKER_DISCONNECTED", "IPC peer disconnected.")),
    );
    socket.once("error", (error) => this.destroy(error));
  }

  public async request(method: string, params: unknown, timeoutMs = 15_000): Promise<unknown> {
    if (this.closed) {
      throw new BrokerRpcError("BROKER_DISCONNECTED", "IPC peer is closed.");
    }
    const id = randomUUID();
    const response = new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new BrokerRpcError("BROKER_TIMEOUT", `Timed out waiting for ${method}.`));
      }, timeoutMs);
      timer.unref();
      this.pending.set(id, { resolve, reject, timer });
    });
    this.send({ v: WIRE_VERSION, kind: "request", id, method, params });
    return response;
  }

  public sendEvent(event: string, payload: unknown): void {
    this.send({ v: WIRE_VERSION, kind: "event", event, payload });
  }

  public close(): void {
    this.socket.end();
  }

  private send(envelope: WireEnvelope): void {
    const serialized = Buffer.from(`${JSON.stringify(envelope)}\n`, "utf8");
    if (serialized.byteLength > MAX_MESSAGE_BYTES) {
      throw new BrokerRpcError("MESSAGE_TOO_LARGE", "IPC message exceeded the 1 MiB limit.");
    }
    this.socket.write(serialized);
  }

  private async receive(value: unknown): Promise<void> {
    const envelope = WireEnvelopeSchema.parse(value);
    if (envelope.kind === "response") {
      const pending = this.pending.get(envelope.id);
      if (pending === undefined) {
        return;
      }
      clearTimeout(pending.timer);
      this.pending.delete(envelope.id);
      if (envelope.ok) {
        pending.resolve(envelope.result);
      } else {
        pending.reject(
          new BrokerRpcError(
            envelope.error?.code ?? "BROKER_ERROR",
            envelope.error?.message ?? "Broker request failed.",
          ),
        );
      }
      return;
    }

    if (envelope.kind === "event") {
      this.onEvent(envelope.event, envelope.payload);
      return;
    }

    if (!this.admitInboundRequest()) {
      this.send({
        v: WIRE_VERSION,
        kind: "response",
        id: envelope.id,
        ok: false,
        error: {
          code: "RATE_LIMITED",
          message: "Too many IPC requests in the fixed one-minute window.",
        },
      });
      return;
    }

    if (this.inboundRequests >= 32) {
      this.send({
        v: WIRE_VERSION,
        kind: "response",
        id: envelope.id,
        ok: false,
        error: { code: "RATE_LIMITED", message: "Too many concurrent IPC requests." },
      });
      return;
    }

    this.inboundRequests += 1;
    try {
      const result = await this.onRequest(envelope.method, envelope.params);
      this.send({ v: WIRE_VERSION, kind: "response", id: envelope.id, ok: true, result });
    } catch (error) {
      const rpcError =
        error instanceof BrokerRpcError
          ? error
          : new BrokerRpcError(
              "INTERNAL_ERROR",
              error instanceof Error ? error.message : "Unknown broker error.",
            );
      this.send({
        v: WIRE_VERSION,
        kind: "response",
        id: envelope.id,
        ok: false,
        error: { code: rpcError.code, message: rpcError.message },
      });
    } finally {
      this.inboundRequests -= 1;
    }
  }

  private admitInboundRequest(): boolean {
    const now = this.now();
    if (
      this.inboundWindowStartedAt === undefined ||
      now < this.inboundWindowStartedAt ||
      now - this.inboundWindowStartedAt >= INBOUND_REQUEST_WINDOW_MS
    ) {
      this.inboundWindowStartedAt = now;
      this.inboundRequestsInWindow = 0;
    }
    if (this.inboundRequestsInWindow >= MAX_INBOUND_REQUESTS_PER_WINDOW) {
      return false;
    }
    this.inboundRequestsInWindow += 1;
    return true;
  }

  private destroy(error: Error): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    if (!this.socket.destroyed) {
      this.socket.destroy();
    }
  }
}
