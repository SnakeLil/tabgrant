import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkNativeHostInstallation } from "../src/doctor.js";
import { writeNativeHostLauncherCreateOnly } from "../src/installer.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0)) {
    if (!directory.startsWith(`${tmpdir()}${sep}tabgrant-doctor-test-`)) continue;
    await rm(directory, { recursive: true, force: true });
  }
});

describe("native-host doctor", () => {
  it("validates the generated launcher, pinned Node runtime, and host entry", async () => {
    const fixture = await installationFixture();
    const launcherPath = join(fixture.manifestDirectory, `io.tabgrant.bridge.${randomUUID()}.host`);
    await writeNativeHostLauncherCreateOnly(
      launcherPath,
      process.execPath,
      fixture.nativeHostEntryPath,
    );
    await writeManifest(fixture.manifestPath, launcherPath);

    const checks = await checkNativeHostInstallation(fixture.manifestPath);

    expect(checks.map(({ name }) => name)).toEqual([
      "native host manifest",
      "native host launcher",
      "pinned Node runtime",
      "native host entry",
    ]);
    expect(checks.every(({ ok }) => ok)).toBe(true);
  });

  it("rejects the legacy env-based Node shebang that fails under GUI PATH", async () => {
    const fixture = await installationFixture();
    const legacyHostPath = join(fixture.directory, "legacy-native-host");
    await writeFile(legacyHostPath, "#!/usr/bin/env node\n", { mode: 0o700 });
    await writeManifest(fixture.manifestPath, legacyHostPath);

    const checks = await checkNativeHostInstallation(fixture.manifestPath);

    expect(checks[0]?.ok).toBe(true);
    expect(checks[1]).toMatchObject({ name: "native host executable", ok: false });
    expect(checks[1]?.detail).toContain("depends on GUI PATH");
  });

  it("reports a missing pinned Node runtime without executing the launcher", async () => {
    const fixture = await installationFixture();
    const launcherPath = join(fixture.manifestDirectory, `io.tabgrant.bridge.${randomUUID()}.host`);
    await writeNativeHostLauncherCreateOnly(
      launcherPath,
      join(fixture.directory, "missing-node"),
      fixture.nativeHostEntryPath,
    );
    await writeManifest(fixture.manifestPath, launcherPath);

    const checks = await checkNativeHostInstallation(fixture.manifestPath);

    expect(checks.find(({ name }) => name === "pinned Node runtime")).toMatchObject({
      ok: false,
    });
    expect(checks.find(({ name }) => name === "native host entry")).toMatchObject({ ok: true });
  });

  it("rejects an invalid allowed origin before inspecting its target", async () => {
    const fixture = await installationFixture();
    await writeFile(
      fixture.manifestPath,
      `${JSON.stringify({
        name: "io.tabgrant.bridge",
        description: "TabGrant local capability broker bridge",
        path: fixture.nativeHostEntryPath,
        type: "stdio",
        allowed_origins: ["chrome-extension://invalid/"],
      })}\n`,
      { mode: 0o600 },
    );

    await expect(checkNativeHostInstallation(fixture.manifestPath)).resolves.toEqual([
      {
        name: "native host manifest",
        ok: false,
        detail: `${fixture.manifestPath} has an invalid TabGrant schema`,
      },
    ]);
  });

  it("rejects a launcher symlink without reading its target", async () => {
    const fixture = await installationFixture();
    const target = join(fixture.directory, "launcher-target");
    const launcherPath = join(fixture.manifestDirectory, `io.tabgrant.bridge.${randomUUID()}.host`);
    await writeNativeHostLauncherCreateOnly(target, process.execPath, fixture.nativeHostEntryPath);
    await symlink(target, launcherPath);
    await writeManifest(fixture.manifestPath, launcherPath);

    const checks = await checkNativeHostInstallation(fixture.manifestPath);

    expect(checks[1]).toMatchObject({ name: "native host executable", ok: false });
  });

  it("reports an unreadable manifest as a structured failed check", async () => {
    const fixture = await installationFixture();
    await writeManifest(fixture.manifestPath, fixture.nativeHostEntryPath);
    await chmod(fixture.manifestPath, 0o200);

    await expect(checkNativeHostInstallation(fixture.manifestPath)).resolves.toEqual([
      {
        name: "native host manifest",
        ok: false,
        detail: `${fixture.manifestPath} is not an owner-only regular manifest`,
      },
    ]);
  });

  it("rejects an unreadable native-host entry", async () => {
    const fixture = await installationFixture();
    const launcherPath = join(fixture.manifestDirectory, `io.tabgrant.bridge.${randomUUID()}.host`);
    await chmod(fixture.nativeHostEntryPath, 0o200);
    await writeNativeHostLauncherCreateOnly(
      launcherPath,
      process.execPath,
      fixture.nativeHostEntryPath,
    );
    await writeManifest(fixture.manifestPath, launcherPath);

    const checks = await checkNativeHostInstallation(fixture.manifestPath);

    expect(checks.find(({ name }) => name === "native host entry")).toMatchObject({ ok: false });
  });

  it("checks effective execute access for the pinned Node runtime", async () => {
    const fixture = await installationFixture();
    const launcherPath = join(fixture.manifestDirectory, `io.tabgrant.bridge.${randomUUID()}.host`);
    const nodePath = join(fixture.directory, "inaccessible-node");
    await writeFile(nodePath, "#!/bin/sh\nexit 0\n", { mode: 0o010 });
    await writeNativeHostLauncherCreateOnly(launcherPath, nodePath, fixture.nativeHostEntryPath);
    await writeManifest(fixture.manifestPath, launcherPath);

    const checks = await checkNativeHostInstallation(fixture.manifestPath);

    expect(checks.find(({ name }) => name === "pinned Node runtime")).toMatchObject({
      ok: false,
    });
  });
});

async function installationFixture(): Promise<{
  directory: string;
  manifestDirectory: string;
  manifestPath: string;
  nativeHostEntryPath: string;
}> {
  const directory = await mkdtemp(join(tmpdir(), "tabgrant-doctor-test-"));
  temporaryDirectories.push(directory);
  const manifestDirectory = join(directory, "NativeMessagingHosts");
  const manifestPath = join(manifestDirectory, "io.tabgrant.bridge.json");
  const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
  await mkdir(manifestDirectory, { mode: 0o700 });
  await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });
  return { directory, manifestDirectory, manifestPath, nativeHostEntryPath };
}

async function writeManifest(manifestPath: string, nativeHostPath: string): Promise<void> {
  await writeFile(
    manifestPath,
    `${JSON.stringify({
      name: "io.tabgrant.bridge",
      description: "TabGrant local capability broker bridge",
      path: nativeHostPath,
      type: "stdio",
      allowed_origins: [`chrome-extension://${"a".repeat(32)}/`],
    })}\n`,
    { mode: 0o600 },
  );
}
