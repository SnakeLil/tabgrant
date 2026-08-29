import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { BrokerClient, BrokerClientIdentity } from "./client.js";
import { connectBroker } from "./client.js";
import type { RuntimePaths } from "./paths.js";
import { getRuntimePaths } from "./paths.js";
import { assertKillSwitchDisabled } from "./kill-switch.js";

export async function connectBrokerWithAutostart(
  identity: BrokerClientIdentity,
  paths: RuntimePaths = getRuntimePaths(),
  onRequest?: (method: string, params: unknown) => Promise<unknown>,
  onEvent?: (event: string, payload: unknown) => void,
): Promise<BrokerClient> {
  await assertKillSwitchDisabled(paths.killSwitchPath);
  try {
    return await connectBroker(identity, paths, onRequest, onEvent);
  } catch (error) {
    if (!isUnavailable(error)) {
      throw error;
    }
  }

  const cliPath = fileURLToPath(new URL("./cli.js", import.meta.url));
  if (!existsSync(cliPath)) {
    throw new Error(
      "TabGrant broker is not running. Start it with `pnpm --filter tabgrant start:daemon` in development.",
    );
  }
  const child = spawn(process.execPath, [cliPath, "daemon", "--quiet"], {
    detached: true,
    stdio: "ignore",
  });
  child.unref();

  let lastError: unknown;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 75));
    try {
      return await connectBroker(identity, paths, onRequest, onEvent);
    } catch (error) {
      lastError = error;
      if (!isUnavailable(error)) {
        throw error;
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error("TabGrant broker did not become ready.");
}

function isUnavailable(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ECONNREFUSED" || code === "EPIPE";
}
