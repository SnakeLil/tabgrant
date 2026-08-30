import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  installNativeHostAtPaths,
  parseNativeHostManifest,
  parseNativeHostLauncher,
  removeFileIfUnchanged,
  uninstallNativeHostAtPath,
  writeFileCreateOnly,
  writeNativeHostLauncherCreateOnly,
} from "../src/installer.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0)) {
    if (!directory.startsWith(`${tmpdir()}${sep}tabgrant-installer-test-`)) continue;
    await rm(directory, { recursive: true, force: true });
  }
});

describe("native-host manifest file ownership", () => {
  it("publishes a mode-0600 file without replacing an existing destination", async () => {
    const directory = await temporaryDirectory();
    const destination = join(directory, "manifest.json");

    await writeFileCreateOnly(destination, "first\n");
    expect(await readFile(destination, "utf8")).toBe("first\n");
    expect((await stat(destination)).mode & 0o777).toBe(0o600);

    await expect(writeFileCreateOnly(destination, "replacement\n")).rejects.toMatchObject({
      code: "EEXIST",
    });
    expect(await readFile(destination, "utf8")).toBe("first\n");
    expect(await readdir(directory)).toEqual(["manifest.json"]);
  });

  it("removes the exact regular file that was inspected", async () => {
    const directory = await temporaryDirectory();
    const destination = join(directory, "manifest.json");
    const contents = Buffer.from("owned\n");
    await writeFile(destination, contents, { mode: 0o600 });

    await expect(removeFileIfUnchanged(destination, contents)).resolves.toBe(true);
    await expect(stat(destination)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(directory)).toEqual([]);
  });

  it("treats an already absent file as an idempotent no-op", async () => {
    const directory = await temporaryDirectory();
    const destination = join(directory, "manifest.json");

    await expect(removeFileIfUnchanged(destination, Buffer.from("owned\n"))).resolves.toBe(false);
    expect(await readdir(directory)).toEqual([]);
  });

  it("preserves a pathname replacement that wins during cleanup", async () => {
    const directory = await temporaryDirectory();
    const destination = join(directory, "manifest.json");
    const original = Buffer.from("owned\n");
    await writeFile(destination, original, { mode: 0o600 });

    await expect(
      removeFileIfUnchanged(destination, original, async () => {
        await unlink(destination);
        await writeFile(destination, "replacement\n", { mode: 0o600 });
      }),
    ).resolves.toBe(false);

    expect(await readFile(destination, "utf8")).toBe("replacement\n");
    expect(await readdir(directory)).toEqual(["manifest.json"]);
  });

  it("preserves an inspected inode if its bytes change during cleanup", async () => {
    const directory = await temporaryDirectory();
    const destination = join(directory, "manifest.json");
    const original = Buffer.from("owned\n");
    await writeFile(destination, original, { mode: 0o600 });

    await expect(
      removeFileIfUnchanged(destination, original, async () => {
        await writeFile(destination, "changed\n", { mode: 0o600 });
      }),
    ).resolves.toBe(false);

    expect(await readFile(destination, "utf8")).toBe("changed\n");
    expect(await readdir(directory)).toEqual(["manifest.json"]);
  });

  it("refuses symlinks and leaves their target untouched", async () => {
    const directory = await temporaryDirectory();
    const target = join(directory, "user-file.json");
    const destination = join(directory, "manifest.json");
    await writeFile(target, "user data\n", { mode: 0o600 });
    await symlink(target, destination);

    await expect(removeFileIfUnchanged(destination, Buffer.from("user data\n"))).resolves.toBe(
      false,
    );
    expect(await readFile(target, "utf8")).toBe("user data\n");
    expect(await readFile(destination, "utf8")).toBe("user data\n");
  });
});

describe("native-host launcher", () => {
  it("starts the pinned Node runtime when GUI PATH contains no Node executable", async () => {
    const directory = await temporaryDirectory();
    const quotedDirectory = join(directory, "path with space and ' quote");
    await mkdir(quotedDirectory);
    const nativeHostPath = join(quotedDirectory, "native host.mjs");
    const launcherPath = join(directory, "native-host-launcher");
    await writeFile(
      nativeHostPath,
      "process.stdout.write(JSON.stringify({ argv: process.argv.slice(2), path: process.env.PATH }));\n",
      { mode: 0o600 },
    );

    await writeNativeHostLauncherCreateOnly(launcherPath, process.execPath, nativeHostPath);

    const result = spawnSync(launcherPath, ["chrome-extension://" + "a".repeat(32) + "/"], {
      env: { PATH: "/usr/bin:/bin" },
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      argv: [`chrome-extension://${"a".repeat(32)}/`],
      path: "/usr/bin:/bin",
    });
    expect((await stat(launcherPath)).mode & 0o777).toBe(0o700);
    expect(parseNativeHostLauncher(await readFile(launcherPath, "utf8"))).toEqual({
      version: 1,
      nodePath: process.execPath,
      nativeHostPath,
    });
  });

  it("publishes the launcher create-only", async () => {
    const directory = await temporaryDirectory();
    const launcherPath = join(directory, "native-host-launcher");
    const nativeHostPath = join(directory, "native-host.mjs");
    await writeFile(nativeHostPath, "// native host\n", { mode: 0o600 });

    await writeNativeHostLauncherCreateOnly(launcherPath, process.execPath, nativeHostPath);
    const original = await readFile(launcherPath, "utf8");
    await expect(
      writeNativeHostLauncherCreateOnly(launcherPath, process.execPath, nativeHostPath),
    ).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(launcherPath, "utf8")).toBe(original);
  });

  it("rejects a launcher whose executable line was modified", async () => {
    const directory = await temporaryDirectory();
    const launcherPath = join(directory, "native-host-launcher");
    const nativeHostPath = join(directory, "native-host.mjs");
    await writeFile(nativeHostPath, "// native host\n", { mode: 0o600 });
    await writeNativeHostLauncherCreateOnly(launcherPath, process.execPath, nativeHostPath);

    const launcher = await readFile(launcherPath, "utf8");
    expect(
      parseNativeHostLauncher(launcher.replace("exec ", "exec /usr/bin/false # ")),
    ).toBeUndefined();
  });

  it("refuses to publish a launcher larger than the parser and doctor limit", async () => {
    const directory = await temporaryDirectory();
    const launcherPath = join(directory, "native-host-launcher");

    await expect(
      writeNativeHostLauncherCreateOnly(
        launcherPath,
        `/${"n".repeat(9_000)}`,
        `/${"h".repeat(9_000)}`,
      ),
    ).rejects.toThrow("exceeds the safe installation file size limit");
    await expect(stat(launcherPath)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("native-host installation", () => {
  it("publishes a manifest pointing to a generated launcher and removes both", async () => {
    const directory = await temporaryDirectory();
    const manifestPath = join(directory, "NativeMessagingHosts", "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });

    const install = await installNativeHostAtPaths(
      { extensionId: "a".repeat(32), browser: "chrome" },
      { manifestPath, nativeHostEntryPath, nodePath: process.execPath },
    );

    const manifest = parseNativeHostManifest(await readFile(manifestPath, "utf8"));
    if (manifest === undefined) throw new Error("Installer produced an invalid manifest.");
    expect(manifest.path).toBe(install.nativeHostPath);
    expect(manifest.allowed_origins).toEqual([`chrome-extension://${"a".repeat(32)}/`]);
    expect(install.nativeHostPath).toMatch(
      /NativeMessagingHosts\/io\.tabgrant\.bridge\.[0-9a-f-]{36}\.host$/,
    );
    expect((await stat(manifestPath)).mode & 0o777).toBe(0o600);
    expect((await stat(install.nativeHostPath)).mode & 0o777).toBe(0o700);
    expect(parseNativeHostLauncher(await readFile(install.nativeHostPath, "utf8"))).toEqual({
      version: 1,
      nodePath: process.execPath,
      nativeHostPath: nativeHostEntryPath,
    });

    await expect(uninstallNativeHostAtPath("chrome", manifestPath)).resolves.toEqual({
      removed: true,
      manifestPath,
      launcherRemoved: true,
    });
    await expect(stat(manifestPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(install.nativeHostPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rolls back its generated launcher when create-only manifest publication loses", async () => {
    const directory = await temporaryDirectory();
    const manifestDirectory = join(directory, "NativeMessagingHosts");
    const manifestPath = join(manifestDirectory, "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    await mkdir(manifestDirectory);
    await writeFile(manifestPath, "existing\n", { mode: 0o600 });
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });

    await expect(
      installNativeHostAtPaths(
        { extensionId: "a".repeat(32), browser: "chrome" },
        { manifestPath, nativeHostEntryPath, nodePath: process.execPath },
      ),
    ).rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(manifestPath, "utf8")).toBe("existing\n");
    expect(await readdir(manifestDirectory)).toEqual(["io.tabgrant.bridge.json"]);
  });

  it("rejects an unreadable native-host entry before publishing a launcher", async () => {
    const directory = await temporaryDirectory();
    const manifestPath = join(directory, "NativeMessagingHosts", "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o200 });

    await expect(
      installNativeHostAtPaths(
        { extensionId: "a".repeat(32), browser: "chrome" },
        { manifestPath, nativeHostEntryPath, nodePath: process.execPath },
      ),
    ).rejects.toThrow("not a safe owner-readable regular file");
    await expect(stat(manifestPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(join(directory, "NativeMessagingHosts"))).toEqual([]);
  });

  it("rejects a group-writable pinned Node runtime", async () => {
    const directory = await temporaryDirectory();
    const manifestPath = join(directory, "NativeMessagingHosts", "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    const nodePath = join(directory, "unsafe-node");
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });
    await writeFile(nodePath, "#!/bin/sh\nexit 0\n", { mode: 0o733 });
    await chmod(nodePath, 0o733);

    await expect(
      installNativeHostAtPaths(
        { extensionId: "a".repeat(32), browser: "chrome" },
        { manifestPath, nativeHostEntryPath, nodePath },
      ),
    ).rejects.toThrow("not an executable regular file");
    await expect(stat(manifestPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("checks that the current process can execute the pinned Node runtime", async () => {
    const directory = await temporaryDirectory();
    const manifestPath = join(directory, "NativeMessagingHosts", "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    const nodePath = join(directory, "inaccessible-node");
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });
    await writeFile(nodePath, "#!/bin/sh\nexit 0\n", { mode: 0o010 });

    await expect(
      installNativeHostAtPaths(
        { extensionId: "a".repeat(32), browser: "chrome" },
        { manifestPath, nativeHostEntryPath, nodePath },
      ),
    ).rejects.toThrow("not executable by the current process");
    await expect(stat(manifestPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("preserves a same-byte launcher replacement that wins after inode pinning", async () => {
    const directory = await temporaryDirectory();
    const manifestPath = join(directory, "NativeMessagingHosts", "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });
    const install = await installNativeHostAtPaths(
      { extensionId: "a".repeat(32), browser: "chrome" },
      { manifestPath, nativeHostEntryPath, nodePath: process.execPath },
    );
    const launcherContents = await readFile(install.nativeHostPath);
    const originalInode = (await stat(install.nativeHostPath)).ino;

    await expect(
      uninstallNativeHostAtPath("chrome", manifestPath, {
        afterLauncherPin: async () => {
          await unlink(install.nativeHostPath);
          await writeFile(install.nativeHostPath, launcherContents, { mode: 0o700 });
        },
      }),
    ).rejects.toThrow("launcher that changed");

    await expect(stat(manifestPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(install.nativeHostPath)).toEqual(launcherContents);
    expect((await stat(install.nativeHostPath)).ino).not.toBe(originalInode);
  });

  it("preserves an unsafe generated launcher during uninstall", async () => {
    const directory = await temporaryDirectory();
    const manifestPath = join(directory, "NativeMessagingHosts", "io.tabgrant.bridge.json");
    const nativeHostEntryPath = join(directory, "native-host-entry.mjs");
    await writeFile(nativeHostEntryPath, "// native host\n", { mode: 0o600 });
    const install = await installNativeHostAtPaths(
      { extensionId: "a".repeat(32), browser: "chrome" },
      { manifestPath, nativeHostEntryPath, nodePath: process.execPath },
    );
    await chmod(install.nativeHostPath, 0o777);

    await expect(uninstallNativeHostAtPath("chrome", manifestPath)).rejects.toThrow(
      "invalid native-host launcher",
    );
    await expect(stat(manifestPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await stat(install.nativeHostPath)).mode & 0o777).toBe(0o777);
  });

  it("never removes a legacy or explicitly supplied native host", async () => {
    const directory = await temporaryDirectory();
    const manifestDirectory = join(directory, "NativeMessagingHosts");
    const manifestPath = join(manifestDirectory, "io.tabgrant.bridge.json");
    const customHostPath = join(directory, "custom-native-host");
    await mkdir(manifestDirectory);
    await writeFile(customHostPath, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await writeFile(
      manifestPath,
      `${JSON.stringify({
        name: "io.tabgrant.bridge",
        description: "TabGrant local capability broker bridge",
        path: customHostPath,
        type: "stdio",
        allowed_origins: [`chrome-extension://${"a".repeat(32)}/`],
      })}\n`,
      { mode: 0o600 },
    );

    await expect(uninstallNativeHostAtPath("chrome", manifestPath)).resolves.toEqual({
      removed: true,
      manifestPath,
      launcherRemoved: false,
    });
    expect(await readFile(customHostPath, "utf8")).toBe("#!/bin/sh\nexit 0\n");
  });
});

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "tabgrant-installer-test-"));
  temporaryDirectories.push(directory);
  return directory;
}
