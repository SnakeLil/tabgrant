import { execFile } from "node:child_process";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { BrokerDaemon } from "../src/daemon.js";
import { clearKillSwitch, readKillSwitch } from "../src/kill-switch.js";
import type { RuntimePaths } from "../src/paths.js";

describe("broker emergency shutdown", () => {
  const execFileAsync = promisify(execFile);
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
  });

  it("survives daemon restart and requires explicit re-enable", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tabgrant-daemon-kill-test-"));
    const paths = testPaths(directory);
    const first = new BrokerDaemon(paths);
    let activeDaemon: BrokerDaemon | undefined = first;
    cleanups.push(async () => {
      await activeDaemon?.stop().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    });
    await first.start();
    const killed = await execFileAsync(
      process.execPath,
      ["--import", "tsx", resolve("src/cli.ts"), "kill"],
      { cwd: resolve("."), env: { ...process.env, TABGRANT_HOME: directory } },
    );
    expect(JSON.parse(killed.stdout)).toMatchObject({
      ok: true,
      killed: true,
      persistent: true,
    });
    await waitForMissing(paths.socketPath);
    activeDaemon = undefined;

    expect(await readKillSwitch(paths.killSwitchPath)).toMatchObject({ active: true });
    const blocked = new BrokerDaemon(paths);
    await expect(blocked.start()).rejects.toThrow(/persistent kill switch|disabled/i);

    await clearKillSwitch(paths.killSwitchPath);
    const restored = new BrokerDaemon(paths);
    activeDaemon = restored;
    await restored.start();
    await expect(access(paths.socketPath)).resolves.toBeUndefined();
  });
});

function testPaths(directory: string): RuntimePaths {
  return {
    baseDirectory: directory,
    runtimeDirectory: join(directory, "run"),
    socketPath: join(directory, "run", "broker.sock"),
    secretPath: join(directory, "broker.secret"),
    authoritySecretPath: join(directory, "authority.secret"),
    auditPath: join(directory, "audit.jsonl"),
    killSwitchPath: join(directory, "disabled.json"),
  };
}

async function waitForMissing(path: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await access(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for path removal: ${path}`);
}
