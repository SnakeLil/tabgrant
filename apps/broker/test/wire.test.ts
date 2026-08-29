import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import type { Socket } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { MAX_MESSAGE_BYTES } from "../src/constants.js";
import {
  INBOUND_REQUEST_WINDOW_MS,
  JsonLineDecoder,
  MAX_INBOUND_REQUESTS_PER_WINDOW,
  RpcPeer,
} from "../src/wire.js";

describe("broker JSON line framing", () => {
  it("accepts multiple individually bounded messages in one chunk", () => {
    const decoder = new JsonLineDecoder();
    const value = "x".repeat(Math.floor(MAX_MESSAGE_BYTES * 0.55));
    const message = Buffer.from(`${JSON.stringify({ value })}\n`);

    expect(decoder.push(Buffer.concat([message, message]))).toHaveLength(2);
  });

  it("rejects a single oversized incomplete message", () => {
    const decoder = new JsonLineDecoder();
    expect(() => decoder.push(Buffer.alloc(MAX_MESSAGE_BYTES + 1, 0x78))).toThrow(/1 MiB/);
  });

  it("rate limits sustained inbound requests before invoking the handler", async () => {
    let now = Date.UTC(2026, 0, 1);
    let handlerCalls = 0;
    const socket = new TestSocket();
    new RpcPeer(
      socket as unknown as Socket,
      () => {
        handlerCalls += 1;
        return Promise.resolve({ handled: true });
      },
      () => undefined,
      () => now,
    );

    const batchSize = 30;
    for (let sent = 0; sent < MAX_INBOUND_REQUESTS_PER_WINDOW; sent += batchSize) {
      const expectedResponses = socket.writes.length + batchSize;
      socket.receiveRequests(batchSize);
      await vi.waitFor(() => expect(socket.writes).toHaveLength(expectedResponses));
    }
    expect(handlerCalls).toBe(MAX_INBOUND_REQUESTS_PER_WINDOW);

    socket.receiveRequests(1);
    await vi.waitFor(() => expect(socket.writes).toHaveLength(MAX_INBOUND_REQUESTS_PER_WINDOW + 1));
    expect(handlerCalls).toBe(MAX_INBOUND_REQUESTS_PER_WINDOW);
    expect(socket.lastResponse()).toMatchObject({
      ok: false,
      error: { code: "RATE_LIMITED" },
    });

    now += INBOUND_REQUEST_WINDOW_MS;
    socket.receiveRequests(1);
    await vi.waitFor(() => expect(socket.writes).toHaveLength(MAX_INBOUND_REQUESTS_PER_WINDOW + 2));
    expect(handlerCalls).toBe(MAX_INBOUND_REQUESTS_PER_WINDOW + 1);
    expect(socket.lastResponse()).toMatchObject({ ok: true, result: { handled: true } });
  });
});

class TestSocket extends EventEmitter {
  public readonly writes: Buffer[] = [];
  public destroyed = false;

  public write(chunk: string | Uint8Array): boolean {
    this.writes.push(Buffer.from(chunk));
    return true;
  }

  public end(): this {
    this.emit("close");
    return this;
  }

  public destroy(): this {
    this.destroyed = true;
    return this;
  }

  public receiveRequests(count: number): void {
    const requests = Array.from({ length: count }, () => ({
      v: 1,
      kind: "request",
      id: randomUUID(),
      method: "test.request",
      params: {},
    }));
    this.emit(
      "data",
      Buffer.from(`${requests.map((request) => JSON.stringify(request)).join("\n")}\n`, "utf8"),
    );
  }

  public lastResponse(): Record<string, unknown> {
    return JSON.parse(this.writes.at(-1)!.toString("utf8")) as Record<string, unknown>;
  }
}
