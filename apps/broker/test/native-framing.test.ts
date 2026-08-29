import { describe, expect, it } from "vitest";
import { MAX_MESSAGE_BYTES } from "../src/constants.js";
import { encodeNativeMessage, NativeMessageDecoder } from "../src/native-framing.js";

describe("Chrome native messaging framing", () => {
  it("decodes fragmented and concatenated frames", () => {
    const first = encodeNativeMessage({ hello: "world" });
    const second = encodeNativeMessage({ count: 2 });
    const combined = Buffer.concat([first, second]);
    const decoder = new NativeMessageDecoder();

    expect(decoder.push(combined.subarray(0, 3))).toEqual([]);
    expect(decoder.push(combined.subarray(3))).toEqual([{ hello: "world" }, { count: 2 }]);
  });

  it("rejects oversized outbound and inbound frames", () => {
    expect(() => encodeNativeMessage({ value: "x".repeat(MAX_MESSAGE_BYTES) })).toThrow(/1 MiB/);
    const header = Buffer.alloc(4);
    header.writeUInt32LE(MAX_MESSAGE_BYTES + 1);
    expect(() => new NativeMessageDecoder().push(header)).toThrow(/1 MiB/);
  });
});
