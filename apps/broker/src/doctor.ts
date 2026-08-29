import { constants } from "node:fs";
import { access, stat } from "node:fs/promises";
import type { BrowserChannel } from "./installer.js";
import { nativeManifestPath } from "./installer.js";
import type { RuntimePaths } from "./paths.js";
import { getRuntimePaths } from "./paths.js";
import { readKillSwitch } from "./kill-switch.js";

export interface DoctorCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export async function runDoctor(
  browser: BrowserChannel,
  paths: RuntimePaths = getRuntimePaths(),
): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  const killSwitch = await readKillSwitch(paths.killSwitchPath);
  checks.push({
    name: "persistent kill switch",
    ok: !killSwitch.active,
    detail: killSwitch.active ? `active since ${killSwitch.activatedAt ?? "unknown"}` : "disabled",
  });
  checks.push(await checkFile("broker secret", paths.secretPath, 0o600));
  checks.push(await checkFile("authority secret", paths.authoritySecretPath, 0o600));
  checks.push(await checkFile("native host manifest", nativeManifestPath(browser), 0o600));
  checks.push(await checkSocket(paths.socketPath));
  return checks;
}

async function checkFile(name: string, path: string, maximumMode: number): Promise<DoctorCheck> {
  try {
    const metadata = await stat(path);
    const mode = metadata.mode & 0o777;
    const ok = metadata.isFile() && (mode & ~maximumMode) === 0;
    return { name, ok, detail: `${path} (mode ${mode.toString(8)})` };
  } catch (error) {
    return {
      name,
      ok: false,
      detail: `${path}: ${(error as NodeJS.ErrnoException).code ?? "unavailable"}`,
    };
  }
}

async function checkSocket(path: string): Promise<DoctorCheck> {
  try {
    await access(path, constants.R_OK | constants.W_OK);
    const metadata = await stat(path);
    return { name: "broker socket", ok: metadata.isSocket(), detail: path };
  } catch (error) {
    return {
      name: "broker socket",
      ok: false,
      detail: `${path}: ${(error as NodeJS.ErrnoException).code ?? "unavailable"}`,
    };
  }
}
