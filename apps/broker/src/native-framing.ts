import type { Readable, Writable } from "node:stream";
import { MAX_MESSAGE_BYTES } from "./constants.js";
import { BrokerRpcError } from "./wire.js";

export function encodeNativeMessage(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  if (body.byteLength > MAX_MESSAGE_BYTES) {
    throw new BrokerRpcError("MESSAGE_TOO_LARGE", "Native message exceeded the 1 MiB limit.");
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32LE(body.byteLength, 0);
  return Buffer.concat([header, body]);
}

export class NativeMessageDecoder {
  private buffer = Buffer.alloc(0);

  public push(chunk: Buffer): unknown[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.byteLength > MAX_MESSAGE_BYTES * 2 + 8) {
      throw new BrokerRpcError(
        "MESSAGE_TOO_LARGE",
        "Native input exceeded the bounded receive buffer.",
      );
    }
    const messages: unknown[] = [];

    while (this.buffer.byteLength >= 4) {
      const length = this.buffer.readUInt32LE(0);
      if (length > MAX_MESSAGE_BYTES) {
        throw new BrokerRpcError("MESSAGE_TOO_LARGE", "Native message exceeded the 1 MiB limit.");
      }
      if (this.buffer.byteLength < length + 4) {
        break;
      }
      const body = this.buffer.subarray(4, length + 4);
      this.buffer = this.buffer.subarray(length + 4);
      messages.push(JSON.parse(body.toString("utf8")) as unknown);
    }

    return messages;
  }
}

export class NativeMessageTransport {
  private readonly decoder = new NativeMessageDecoder();

  public constructor(
    input: Readable,
    private readonly output: Writable,
    onMessage: (message: unknown) => void,
    onError: (error: Error) => void,
  ) {
    input.on("data", (chunk: Buffer) => {
      try {
        for (const message of this.decoder.push(chunk)) {
          onMessage(message);
        }
      } catch (error) {
        onError(error instanceof Error ? error : new Error(String(error)));
      }
    });
    input.on("error", onError);
  }

  public send(message: unknown): void {
    this.output.write(encodeNativeMessage(message));
  }
}
