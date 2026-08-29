import { describe, expect, it } from "vitest";
import { SerialQueue } from "./serial-queue.js";

function deferred(): {
  promise: Promise<void>;
  resolve: () => void;
} {
  let resolve: (() => void) | undefined;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return {
    promise,
    resolve: () => resolve?.(),
  };
}

describe("browser authentication serialization", () => {
  it("prevents a late initial auth start from invalidating a pairing challenge", async () => {
    const queue = new SerialQueue();
    const initialAuthLookup = deferred();
    const events: string[] = [];
    let activeChallenge: string | undefined;

    const initialAuthentication = queue.run(async () => {
      events.push("auth:start");
      await initialAuthLookup.promise;
      activeChallenge = undefined;
      events.push("auth:unpaired");
    });
    const pairing = queue.run(async () => {
      events.push("pair:start");
      activeChallenge = "pair-challenge";
      await Promise.resolve();
      expect(activeChallenge).toBe("pair-challenge");
      events.push("pair:complete");
    });

    await Promise.resolve();
    expect(events).toEqual(["auth:start"]);
    initialAuthLookup.resolve();
    await Promise.all([initialAuthentication, pairing]);
    expect(events).toEqual(["auth:start", "auth:unpaired", "pair:start", "pair:complete"]);
  });

  it("continues with a queued pairing attempt after initial authentication rejects", async () => {
    const queue = new SerialQueue();
    const events: string[] = [];

    const initialAuthentication = queue.run(() => {
      events.push("auth:start");
      return Promise.reject(new Error("relay disconnected"));
    });
    const pairing = queue.run(() => {
      events.push("pair:start");
      return Promise.resolve("paired");
    });

    await expect(initialAuthentication).rejects.toThrow("relay disconnected");
    await expect(pairing).resolves.toBe("paired");
    expect(events).toEqual(["auth:start", "pair:start"]);
  });
});
