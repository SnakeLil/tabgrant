import { constants, type Stats } from "node:fs";
import { access, lstat, readFile } from "node:fs/promises";
import { readKillSwitch } from "./kill-switch.js";
import type { BrowserChannel } from "./installer.js";
import {
  isGeneratedNativeHostLauncherPath,
  MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES,
  nativeManifestPath,
  parseNativeHostLauncher,
  parseNativeHostManifest,
} from "./installer.js";
import type { RuntimePaths } from "./paths.js";
import { getRuntimePaths } from "./paths.js";

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
  checks.push(...(await checkNativeHostInstallation(nativeManifestPath(browser))));
  checks.push(await checkSocket(paths.socketPath));
  return checks;
}

export async function checkNativeHostInstallation(manifestPath: string): Promise<DoctorCheck[]> {
  let manifestMetadata: Stats;
  try {
    manifestMetadata = await lstat(manifestPath);
  } catch (error) {
    return [failure("native host manifest", manifestPath, error)];
  }
  const manifestMode = manifestMetadata.mode & 0o777;
  if (
    !manifestMetadata.isFile() ||
    manifestMetadata.isSymbolicLink() ||
    (manifestMode & ~0o600) !== 0 ||
    (manifestMode & 0o400) === 0 ||
    !ownedByCurrentUser(manifestMetadata) ||
    manifestMetadata.size > MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES
  ) {
    return [
      {
        name: "native host manifest",
        ok: false,
        detail: `${manifestPath} is not an owner-only regular manifest`,
      },
    ];
  }

  let manifestContents: string;
  try {
    await access(manifestPath, constants.R_OK);
    manifestContents = await readFile(manifestPath, "utf8");
  } catch (error) {
    return [failure("native host manifest", manifestPath, error)];
  }
  const manifest = parseNativeHostManifest(manifestContents);
  if (manifest === undefined) {
    return [
      {
        name: "native host manifest",
        ok: false,
        detail: `${manifestPath} has an invalid TabGrant schema`,
      },
    ];
  }

  const checks: DoctorCheck[] = [
    {
      name: "native host manifest",
      ok: true,
      detail: `${manifestPath} -> ${manifest.path} (${manifest.allowed_origins[0]})`,
    },
  ];
  checks.push(...(await checkNativeHostTarget(manifest.path, manifestPath)));
  return checks;
}

async function checkNativeHostTarget(
  nativeHostPath: string,
  manifestPath: string,
): Promise<DoctorCheck[]> {
  let metadata: Stats;
  try {
    metadata = await lstat(nativeHostPath);
  } catch (error) {
    return [failure("native host executable", nativeHostPath, error)];
  }
  const mode = metadata.mode & 0o777;
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    (mode & 0o500) !== 0o500 ||
    (mode & 0o022) !== 0 ||
    !ownedByCurrentUser(metadata)
  ) {
    return [
      {
        name: "native host executable",
        ok: false,
        detail: `${nativeHostPath} is not a safe owner-executable regular file`,
      },
    ];
  }
  try {
    await access(nativeHostPath, constants.R_OK | constants.X_OK);
  } catch (error) {
    return [failure("native host executable", nativeHostPath, error)];
  }

  if (isGeneratedNativeHostLauncherPath(nativeHostPath, manifestPath)) {
    if ((mode & ~0o700) !== 0 || metadata.size > MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES) {
      return [
        {
          name: "native host launcher",
          ok: false,
          detail: `${nativeHostPath} must be an owner-only bounded launcher`,
        },
      ];
    }
    let launcherContents: string;
    try {
      launcherContents = await readFile(nativeHostPath, "utf8");
    } catch (error) {
      return [failure("native host launcher", nativeHostPath, error)];
    }
    const launcher = parseNativeHostLauncher(launcherContents);
    if (launcher === undefined) {
      return [
        {
          name: "native host launcher",
          ok: false,
          detail: `${nativeHostPath} is not a canonical TabGrant launcher`,
        },
      ];
    }
    return [
      {
        name: "native host launcher",
        ok: true,
        detail: `${nativeHostPath} (mode ${mode.toString(8)})`,
      },
      await checkExecutable("pinned Node runtime", launcher.nodePath, false),
      await checkReadableEntry(launcher.nativeHostPath),
    ];
  }

  if (metadata.size <= MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES) {
    let contents: string;
    try {
      contents = await readFile(nativeHostPath, "utf8");
    } catch (error) {
      return [failure("native host executable", nativeHostPath, error)];
    }
    if (contents.startsWith("#!/usr/bin/env node\n")) {
      return [
        {
          name: "native host executable",
          ok: false,
          detail: `${nativeHostPath} depends on GUI PATH; uninstall and reinstall to generate a pinned launcher`,
        },
      ];
    }
  }
  return [
    {
      name: "native host executable",
      ok: true,
      detail: `${nativeHostPath} (custom executable, mode ${mode.toString(8)})`,
    },
  ];
}

async function checkExecutable(
  name: string,
  path: string,
  requireOwnership: boolean,
): Promise<DoctorCheck> {
  let metadata: Stats;
  try {
    metadata = await lstat(path);
  } catch (error) {
    return failure(name, path, error);
  }
  const mode = metadata.mode & 0o777;
  const structurallySafe =
    metadata.isFile() &&
    !metadata.isSymbolicLink() &&
    (mode & 0o111) !== 0 &&
    (mode & 0o022) === 0 &&
    (!requireOwnership || ownedByCurrentUser(metadata));
  if (structurallySafe) {
    try {
      await access(path, constants.X_OK);
    } catch (error) {
      return failure(name, path, error);
    }
  }
  return {
    name,
    ok: structurallySafe,
    detail: structurallySafe
      ? `${path} (mode ${mode.toString(8)})`
      : `${path} is not a safe executable regular file`,
  };
}

async function checkReadableEntry(path: string): Promise<DoctorCheck> {
  let metadata: Stats;
  try {
    metadata = await lstat(path);
  } catch (error) {
    return failure("native host entry", path, error);
  }
  const mode = metadata.mode & 0o777;
  const ok =
    metadata.isFile() &&
    !metadata.isSymbolicLink() &&
    (mode & 0o400) !== 0 &&
    (mode & 0o022) === 0 &&
    ownedByCurrentUser(metadata);
  if (ok) {
    try {
      await access(path, constants.R_OK);
    } catch (error) {
      return failure("native host entry", path, error);
    }
  }
  return {
    name: "native host entry",
    ok,
    detail: ok ? `${path} (mode ${mode.toString(8)})` : `${path} is not a safe regular file`,
  };
}

async function checkFile(name: string, path: string, maximumMode: number): Promise<DoctorCheck> {
  try {
    const metadata = await lstat(path);
    const mode = metadata.mode & 0o777;
    const structurallySafe =
      metadata.isFile() &&
      !metadata.isSymbolicLink() &&
      (mode & ~maximumMode) === 0 &&
      (mode & 0o400) !== 0 &&
      ownedByCurrentUser(metadata);
    if (structurallySafe) await access(path, constants.R_OK);
    return { name, ok: structurallySafe, detail: `${path} (mode ${mode.toString(8)})` };
  } catch (error) {
    return failure(name, path, error);
  }
}

async function checkSocket(path: string): Promise<DoctorCheck> {
  try {
    await access(path, constants.R_OK | constants.W_OK);
    const metadata = await lstat(path);
    return { name: "broker socket", ok: metadata.isSocket(), detail: path };
  } catch (error) {
    return failure("broker socket", path, error);
  }
}

function ownedByCurrentUser(metadata: Stats): boolean {
  return typeof process.getuid !== "function" || metadata.uid === process.getuid();
}

function failure(name: string, path: string, error: unknown): DoctorCheck {
  return {
    name,
    ok: false,
    detail: `${path}: ${(error as NodeJS.ErrnoException).code ?? "unavailable"}`,
  };
}
