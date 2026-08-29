import { homedir, platform, tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

export interface RuntimePaths {
  readonly baseDirectory: string;
  readonly runtimeDirectory: string;
  readonly socketPath: string;
  readonly secretPath: string;
  readonly authoritySecretPath: string;
  readonly auditPath: string;
  readonly killSwitchPath: string;
}

function configuredBaseDirectory(environment: NodeJS.ProcessEnv): string | undefined {
  const configured = environment.TABGRANT_HOME;
  if (configured === undefined || configured.trim() === "") {
    return undefined;
  }

  return isAbsolute(configured) ? configured : resolve(configured);
}

export function getRuntimePaths(environment: NodeJS.ProcessEnv = process.env): RuntimePaths {
  const configured = configuredBaseDirectory(environment);
  let baseDirectory: string;

  if (configured !== undefined) {
    baseDirectory = configured;
  } else if (platform() === "darwin") {
    baseDirectory = join(homedir(), "Library", "Application Support", "TabGrant");
  } else if (platform() === "win32") {
    baseDirectory = join(environment.LOCALAPPDATA ?? tmpdir(), "TabGrant");
  } else {
    baseDirectory = join(
      environment.XDG_STATE_HOME ?? join(homedir(), ".local", "state"),
      "tabgrant",
    );
  }

  const runtimeDirectory =
    platform() === "linux" && environment.XDG_RUNTIME_DIR
      ? join(environment.XDG_RUNTIME_DIR, "tabgrant")
      : join(baseDirectory, "run");

  const socketPath =
    platform() === "win32"
      ? `\\\\.\\pipe\\tabgrant-${process.env.USERNAME ?? "user"}`
      : join(runtimeDirectory, "broker.sock");

  return {
    baseDirectory,
    runtimeDirectory,
    socketPath,
    secretPath: join(baseDirectory, "broker.secret"),
    authoritySecretPath: join(baseDirectory, "authority.secret"),
    auditPath: join(baseDirectory, "audit.jsonl"),
    killSwitchPath: join(baseDirectory, "disabled.json"),
  };
}

export function parentDirectory(path: string): string {
  return dirname(path);
}
