import { mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { spawnSync } from "node:child_process";

const temporaryDirectory = await mkdtemp(join(tmpdir(), "tabgrant-pack-"));

try {
  run("pnpm", ["--filter", "tabgrant", "pack", "--pack-destination", temporaryDirectory]);
  const tarballName = (await readdir(temporaryDirectory)).find((name) => name.endsWith(".tgz"));
  if (!tarballName) throw new Error("pnpm pack did not produce a tarball");

  await writeFile(
    join(temporaryDirectory, "package.json"),
    `${JSON.stringify({ private: true, name: "tabgrant-pack-smoke" })}\n`,
  );
  run(
    "npm",
    [
      "install",
      join(temporaryDirectory, tarballName),
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    temporaryDirectory,
  );

  const installedPackageDirectory = join(temporaryDirectory, "node_modules", "tabgrant");
  const installedPackagePath = join(installedPackageDirectory, "package.json");
  const installed = JSON.parse(await readFile(installedPackagePath, "utf8"));
  const sourcePackage = JSON.parse(
    await readFile(new URL("../apps/broker/package.json", import.meta.url), "utf8"),
  );
  for (const field of [
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "bugs",
    "license",
    "type",
    "engines",
  ]) {
    if (JSON.stringify(installed[field]) !== JSON.stringify(sourcePackage[field])) {
      throw new Error(`packed package has unexpected ${field} metadata`);
    }
  }
  const expectedBins = {
    tabgrant: "dist/cli.js",
    "tabgrant-mcp": "dist/mcp-entry.js",
    "tabgrant-native-host": "dist/native-host-entry.js",
  };
  if (JSON.stringify(installed.bin) !== JSON.stringify(expectedBins)) {
    throw new Error("packed package has unexpected bin metadata");
  }
  for (const value of Object.values(installed.dependencies ?? {})) {
    if (String(value).startsWith("workspace:"))
      throw new Error("packed package contains a workspace dependency");
  }
  const packedLicense = await readFile(join(installedPackageDirectory, "LICENSE"), "utf8");
  const sourceLicense = await readFile(new URL("../LICENSE", import.meta.url), "utf8");
  if (packedLicense !== sourceLicense) {
    throw new Error("packed package does not contain the complete project LICENSE");
  }
  for (const [binName, relativePath] of Object.entries(expectedBins)) {
    const executablePath = join(installedPackageDirectory, relativePath);
    const executable = await readFile(executablePath, "utf8");
    if (!executable.startsWith("#!/usr/bin/env node\n")) {
      throw new Error(`packed ${binName} executable is missing its Node.js shebang`);
    }
    if (process.platform !== "win32" && ((await stat(executablePath)).mode & 0o111) === 0) {
      throw new Error(`packed ${binName} executable is not executable`);
    }
  }
  const installedCli = join(installedPackageDirectory, expectedBins.tabgrant);
  const result = run(process.execPath, [installedCli, "version"], temporaryDirectory);
  if (result.trim() !== installed.version) {
    throw new Error(
      `packed CLI returned ${JSON.stringify(result.trim())}, expected ${installed.version}`,
    );
  }

  const isolatedHome = join(temporaryDirectory, "home");
  const isolatedEnvironment = {
    ...process.env,
    HOME: isolatedHome,
    TABGRANT_HOME: join(temporaryDirectory, "state"),
    XDG_CONFIG_HOME: join(isolatedHome, ".config"),
    XDG_STATE_HOME: join(isolatedHome, ".local", "state"),
  };
  const install = JSON.parse(
    run(
      process.execPath,
      [installedCli, "install", "--extension-id", "a".repeat(32), "--browser", "chrome"],
      temporaryDirectory,
      isolatedEnvironment,
    ),
  );
  if (
    typeof install.manifestPath !== "string" ||
    !install.manifestPath.startsWith(`${isolatedHome}${sep}`)
  ) {
    throw new Error("packed installer escaped its isolated home");
  }
  const manifest = JSON.parse(await readFile(install.manifestPath, "utf8"));
  if (
    manifest.name !== "io.tabgrant.bridge" ||
    manifest.path !== install.nativeHostPath ||
    manifest.type !== "stdio" ||
    JSON.stringify(manifest.allowed_origins) !==
      JSON.stringify([`chrome-extension://${"a".repeat(32)}/`])
  ) {
    throw new Error("packed installer produced an unexpected native-host manifest");
  }
  const packedNativeHostEntry = join(installedPackageDirectory, "dist", "native-host-entry.js");
  if (install.nativeHostPath === packedNativeHostEntry) {
    throw new Error("packed installer bypassed the pinned native-host launcher");
  }
  const launcherMetadata = await stat(install.nativeHostPath);
  if (process.platform !== "win32" && (launcherMetadata.mode & 0o777) !== 0o700) {
    throw new Error("packed native-host launcher permissions are not 0700");
  }
  const launcherLines = (await readFile(install.nativeHostPath, "utf8")).split("\n");
  const marker = "# tabgrant-native-host-launcher-v1:";
  if (
    launcherLines.length !== 4 ||
    launcherLines[0] !== "#!/bin/sh" ||
    !launcherLines[1]?.startsWith(marker)
  ) {
    throw new Error("packed installer produced an unrecognized native-host launcher");
  }
  const launcher = JSON.parse(
    Buffer.from(launcherLines[1].slice(marker.length), "base64url").toString("utf8"),
  );
  const expectedNativeHostEntry = await realpath(packedNativeHostEntry);
  if (
    launcher.version !== 1 ||
    launcher.nodePath !== (await realpath(process.execPath)) ||
    launcher.nativeHostPath !== expectedNativeHostEntry
  ) {
    throw new Error(
      `packed native-host launcher did not pin the expected runtime and entry: ${JSON.stringify({ launcher, expectedNodePath: await realpath(process.execPath), expectedNativeHostEntry })}`,
    );
  }
  const uninstall = JSON.parse(
    run(
      process.execPath,
      [installedCli, "uninstall", "--browser", "chrome"],
      temporaryDirectory,
      isolatedEnvironment,
    ),
  );
  if (uninstall.removed !== true || uninstall.launcherRemoved !== true) {
    throw new Error("packed native-host uninstall smoke failed");
  }
  try {
    await stat(install.nativeHostPath);
    throw new Error("packed native-host uninstall left its generated launcher behind");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const repeatedUninstall = JSON.parse(
    run(
      process.execPath,
      [installedCli, "uninstall", "--browser", "chrome"],
      temporaryDirectory,
      isolatedEnvironment,
    ),
  );
  if (repeatedUninstall.removed !== false) {
    throw new Error("packed native-host uninstall is not idempotent");
  }
  process.stdout.write(`Packed tabgrant@${installed.version} smoke test passed.\n`);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

function run(command, args, cwd = process.cwd(), env = process.env) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed:\n${result.stderr || result.stdout}`);
  }
  return result.stdout;
}
