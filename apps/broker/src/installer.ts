import { randomUUID } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  access,
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { NATIVE_HOST_NAME } from "./constants.js";

export const BrowserChannelSchema = z.enum([
  "chrome",
  "chrome-for-testing",
  "chromium",
  "edge",
  "brave",
]);
export type BrowserChannel = z.infer<typeof BrowserChannelSchema>;

const ExtensionIdSchema = z
  .string()
  .regex(/^[a-p]{32}$/, "Expected a 32-character Chromium extension ID.");

export interface NativeHostManifest {
  readonly name: typeof NATIVE_HOST_NAME;
  readonly description: string;
  readonly path: string;
  readonly type: "stdio";
  readonly allowed_origins: [string];
}

const MANIFEST_DESCRIPTION = "TabGrant local capability broker bridge";
export const MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES = 16_384;
const NATIVE_HOST_LAUNCHER_MARKER = "# tabgrant-native-host-launcher-v1:";
const NATIVE_HOST_LAUNCHER_BASENAME = new RegExp(
  `^${NATIVE_HOST_NAME.replaceAll(".", "\\.")}\\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.host$`,
  "i",
);
const NativeHostLauncherSchema = z
  .object({
    version: z.literal(1),
    nodePath: z
      .string()
      .min(1)
      .regex(/^[^\0\r\n]+$/),
    nativeHostPath: z
      .string()
      .min(1)
      .regex(/^[^\0\r\n]+$/),
  })
  .strict()
  .refine((value) => isAbsolute(value.nodePath) && isAbsolute(value.nativeHostPath));

export interface NativeHostLauncher {
  readonly version: 1;
  readonly nodePath: string;
  readonly nativeHostPath: string;
}

export interface InstallOptions {
  readonly extensionId: string;
  readonly browser: BrowserChannel;
  readonly hostPath?: string;
}

export interface InstallResult {
  readonly manifestPath: string;
  readonly nativeHostPath: string;
  readonly extensionId: string;
  readonly browser: BrowserChannel;
}

export interface NativeHostInstallationPaths {
  readonly manifestPath: string;
  readonly nativeHostEntryPath: string;
  readonly nodePath: string;
}

export interface NativeHostUninstallHooks {
  readonly afterLauncherPin?: () => Promise<void>;
}

export async function installNativeHost(options: InstallOptions): Promise<InstallResult> {
  const browser = BrowserChannelSchema.parse(options.browser);
  return installNativeHostAtPaths(options, {
    manifestPath: nativeManifestPath(browser),
    nativeHostEntryPath: defaultNativeHostPath(),
    nodePath: process.execPath,
  });
}

export async function installNativeHostAtPaths(
  options: InstallOptions,
  paths: NativeHostInstallationPaths,
): Promise<InstallResult> {
  const extensionId = ExtensionIdSchema.parse(options.extensionId);
  const browser = BrowserChannelSchema.parse(options.browser);
  const manifestPath = resolve(paths.manifestPath);
  const manifestDirectory = await prepareManifestDirectory(manifestPath);
  let generatedLauncher: { path: string; contents: string } | undefined;
  let nativeHostPath: string;
  if (options.hostPath === undefined) {
    const nativeHostEntryPath = resolve(paths.nativeHostEntryPath);
    await requireOwnedReadableRegularFile(nativeHostEntryPath, "Native host entry");
    const nodePath = await realpath(paths.nodePath);
    await requireExecutableFile(nodePath, "Node runtime", false);
    nativeHostPath = join(manifestDirectory, `${NATIVE_HOST_NAME}.${randomUUID()}.host`);
    const contents = await writeNativeHostLauncherCreateOnly(
      nativeHostPath,
      nodePath,
      nativeHostEntryPath,
    );
    generatedLauncher = { path: nativeHostPath, contents };
  } else {
    nativeHostPath = resolve(options.hostPath);
    await requireOwnedRegularFile(nativeHostPath, "Native host");
    await chmod(nativeHostPath, 0o755);
  }

  const manifest: NativeHostManifest = {
    name: NATIVE_HOST_NAME,
    description: MANIFEST_DESCRIPTION,
    path: nativeHostPath,
    type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`],
  };
  try {
    await writeFileCreateOnly(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  } catch (error) {
    if (generatedLauncher !== undefined) {
      const removed = await removeFileIfUnchanged(
        generatedLauncher.path,
        Buffer.from(generatedLauncher.contents),
      ).catch((cleanupError: unknown) => {
        throw new AggregateError(
          [error, cleanupError],
          `TabGrant could not publish the manifest or safely roll back ${generatedLauncher.path}.`,
        );
      });
      if (!removed) {
        throw new AggregateError(
          [error],
          `TabGrant could not publish the manifest and preserved a changed launcher at ${generatedLauncher.path}.`,
          { cause: error },
        );
      }
    }
    throw error;
  }
  return { manifestPath, nativeHostPath, extensionId, browser };
}

export async function uninstallNativeHost(
  browser: BrowserChannel,
): Promise<{ removed: boolean; manifestPath: string; launcherRemoved: boolean }> {
  return uninstallNativeHostAtPath(
    browser,
    nativeManifestPath(BrowserChannelSchema.parse(browser)),
  );
}

export async function uninstallNativeHostAtPath(
  browser: BrowserChannel,
  manifestPathInput: string,
  hooks: NativeHostUninstallHooks = {},
): Promise<{ removed: boolean; manifestPath: string; launcherRemoved: boolean }> {
  BrowserChannelSchema.parse(browser);
  const manifestPath = resolve(manifestPathInput);
  let installedHostPath: string | undefined;
  const removal = await removeFileIfMatching(
    manifestPath,
    (contents) => {
      let parsed: Partial<NativeHostManifest>;
      try {
        parsed = JSON.parse(contents.toString("utf8")) as Partial<NativeHostManifest>;
      } catch {
        throw new Error(`Refusing to remove a malformed native-host manifest: ${manifestPath}`);
      }
      if (!isOwnedManifest(parsed)) {
        throw new Error(`Refusing to remove a manifest not owned by TabGrant: ${manifestPath}`);
      }
      installedHostPath = parsed.path;
    },
    undefined,
    MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES,
  );
  if (removal === "missing") return { removed: false, manifestPath, launcherRemoved: false };
  if (removal === "changed") {
    throw new Error(`Refusing to remove a native-host manifest that changed: ${manifestPath}`);
  }
  const launcherRemoved =
    installedHostPath === undefined
      ? false
      : await removeGeneratedLauncherIfOwned(
          installedHostPath,
          manifestPath,
          hooks.afterLauncherPin,
        );
  return { removed: true, manifestPath, launcherRemoved };
}

/**
 * Publishes a file without ever replacing an existing path. The hard-link step is
 * atomic on supported filesystems and fails with EEXIST if another installer won.
 */
export async function writeFileCreateOnly(
  destinationPath: string,
  contents: string,
  mode = 0o600,
): Promise<void> {
  const temporaryPath = `${destinationPath}.${process.pid}.${randomUUID()}.tmp`;
  let handle;
  let published = false;
  try {
    handle = await open(temporaryPath, "wx", mode);
    await handle.writeFile(contents, "utf8");
    await handle.chmod(mode);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporaryPath, destinationPath);
    published = true;
  } finally {
    await handle?.close().catch(() => undefined);
    await unlink(temporaryPath).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return;
      if (!published) throw error;
      process.emitWarning(
        `TabGrant installed ${destinationPath}, but could not remove temporary hard link ${temporaryPath}: ${error.message}`,
        { code: "TABGRANT_INSTALL_CLEANUP" },
      );
    });
  }
}

export async function writeNativeHostLauncherCreateOnly(
  destinationPath: string,
  nodePath: string,
  nativeHostPath: string,
): Promise<string> {
  const launcher = NativeHostLauncherSchema.parse({
    version: 1,
    nodePath,
    nativeHostPath,
  });
  const contents = renderNativeHostLauncher(launcher);
  if (Buffer.byteLength(contents, "utf8") > MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES) {
    throw new Error("Native-host launcher exceeds the safe installation file size limit.");
  }
  await writeFileCreateOnly(destinationPath, contents, 0o700);
  return contents;
}

export function parseNativeHostLauncher(contents: string): NativeHostLauncher | undefined {
  if (Buffer.byteLength(contents, "utf8") > MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES)
    return undefined;
  const lines = contents.split("\n");
  if (lines.length !== 4 || lines[0] !== "#!/bin/sh" || lines[3] !== "") return undefined;
  const encoded = lines[1]?.startsWith(NATIVE_HOST_LAUNCHER_MARKER)
    ? lines[1].slice(NATIVE_HOST_LAUNCHER_MARKER.length)
    : undefined;
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) return undefined;
  let parsed: unknown;
  try {
    const metadata = Buffer.from(encoded, "base64url");
    if (metadata.toString("base64url") !== encoded) return undefined;
    parsed = JSON.parse(metadata.toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
  const launcher = NativeHostLauncherSchema.safeParse(parsed);
  if (!launcher.success || renderNativeHostLauncher(launcher.data) !== contents) return undefined;
  return launcher.data;
}

export function parseNativeHostManifest(contents: string): NativeHostManifest | undefined {
  if (Buffer.byteLength(contents, "utf8") > MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES)
    return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents) as unknown;
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const candidate = parsed as Partial<NativeHostManifest>;
  return isOwnedManifest(candidate) ? candidate : undefined;
}

export function isGeneratedNativeHostLauncherPath(
  launcherPath: string,
  manifestPath: string,
): boolean {
  const launcherDirectory = dirname(manifestPath);
  const relativePath = relative(launcherDirectory, launcherPath);
  return (
    relativePath !== "" &&
    !relativePath.startsWith("..") &&
    !isAbsolute(relativePath) &&
    dirname(relativePath) === "." &&
    NATIVE_HOST_LAUNCHER_BASENAME.test(relativePath)
  );
}

function renderNativeHostLauncher(launcher: NativeHostLauncher): string {
  const metadata = Buffer.from(JSON.stringify(launcher), "utf8").toString("base64url");
  return [
    "#!/bin/sh",
    `${NATIVE_HOST_LAUNCHER_MARKER}${metadata}`,
    `exec ${quoteShellWord(launcher.nodePath)} ${quoteShellWord(launcher.nativeHostPath)} "$@"`,
    "",
  ].join("\n");
}

function quoteShellWord(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function prepareManifestDirectory(manifestPath: string): Promise<string> {
  const manifestDirectory = dirname(manifestPath);
  await mkdir(manifestDirectory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(manifestDirectory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Refusing insecure native-host manifest directory: ${manifestDirectory}`);
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`Refusing native-host directory owned by another user: ${manifestDirectory}`);
  }
  if (platform() !== "win32") await chmod(manifestDirectory, 0o700);
  return manifestDirectory;
}

async function removeGeneratedLauncherIfOwned(
  launcherPath: string,
  manifestPath: string,
  afterPin?: () => Promise<void>,
): Promise<boolean> {
  if (!isGeneratedNativeHostLauncherPath(launcherPath, manifestPath)) return false;
  const removal = await removeFileIfMatching(
    launcherPath,
    (contents, metadata) => {
      const mode = metadata.mode & 0o777;
      if (
        !metadata.isFile() ||
        metadata.isSymbolicLink() ||
        metadata.size > MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES ||
        (mode & ~0o700) !== 0 ||
        (mode & 0o500) !== 0o500
      ) {
        throw new Error(`Refusing to remove an invalid native-host launcher: ${launcherPath}`);
      }
      if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
        throw new Error(`Refusing launcher owned by another user: ${launcherPath}`);
      }
      if (parseNativeHostLauncher(contents.toString("utf8")) === undefined) {
        throw new Error(`Refusing to remove an unrecognized native-host launcher: ${launcherPath}`);
      }
    },
    afterPin,
    MAX_NATIVE_HOST_INSTALLATION_FILE_BYTES,
  );
  if (removal === "missing") return false;
  if (removal === "changed") {
    throw new Error(`Refusing to remove a native-host launcher that changed: ${launcherPath}`);
  }
  return true;
}

async function requireOwnedRegularFile(path: string, label: string): Promise<Stats> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file: ${path}`);
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`Refusing ${label.toLowerCase()} owned by another user: ${path}`);
  }
  return metadata;
}

async function requireOwnedReadableRegularFile(path: string, label: string): Promise<void> {
  const metadata = await requireOwnedRegularFile(path, label);
  const mode = metadata.mode & 0o777;
  if ((mode & 0o400) === 0 || (mode & 0o022) !== 0) {
    throw new Error(`${label} is not a safe owner-readable regular file: ${path}`);
  }
  try {
    await access(path, constants.R_OK);
  } catch (error) {
    throw new Error(`${label} is not readable by the current process: ${path}`, { cause: error });
  }
}

async function requireExecutableFile(
  path: string,
  label: string,
  requireOwnership = true,
): Promise<void> {
  const metadata = await lstat(path);
  const mode = metadata.mode & 0o777;
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    (mode & 0o111) === 0 ||
    (mode & 0o022) !== 0
  ) {
    throw new Error(`${label} is not an executable regular file: ${path}`);
  }
  if (
    requireOwnership &&
    typeof process.getuid === "function" &&
    metadata.uid !== process.getuid()
  ) {
    throw new Error(`Refusing ${label.toLowerCase()} owned by another user: ${path}`);
  }
  try {
    await access(path, constants.X_OK);
  } catch (error) {
    throw new Error(`${label} is not executable by the current process: ${path}`, { cause: error });
  }
}

/**
 * Removes only the exact regular-file inode and bytes that the caller inspected.
 * A unique hard link pins the inspected inode while an atomic rename detects a
 * concurrent pathname replacement without deleting the replacement.
 */
export async function removeFileIfUnchanged(
  targetPath: string,
  expectedBytes: Uint8Array,
  afterPin?: () => Promise<void>,
): Promise<boolean> {
  try {
    return (
      (await removeFileIfMatching(
        targetPath,
        (contents) => {
          if (!contents.equals(Buffer.from(expectedBytes))) throw new FileMismatchError();
        },
        afterPin,
      )) === "removed"
    );
  } catch (error) {
    if (error instanceof FileMismatchError) return false;
    throw error;
  }
}

async function removeFileIfMatching(
  targetPath: string,
  validate: (contents: Buffer, metadata: Stats) => void,
  afterPin?: () => Promise<void>,
  maximumBytes?: number,
): Promise<"removed" | "missing" | "changed"> {
  const token = `${process.pid}.${randomUUID()}`;
  const pinnedPath = `${targetPath}.${token}.pinned`;
  const movedPath = `${targetPath}.${token}.remove`;
  let moved = false;
  let operationError: unknown;
  let cleanupError: AggregateError | undefined;
  let result: "removed" | "changed" = "changed";
  try {
    await link(targetPath, pinnedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    throw error;
  }
  try {
    const pinnedMetadata = await lstat(pinnedPath);
    if (pinnedMetadata.isFile() && !pinnedMetadata.isSymbolicLink()) {
      const handle = await open(pinnedPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      let pinnedBytes: Buffer;
      let descriptorMetadata: Stats;
      try {
        descriptorMetadata = await handle.stat();
        if (maximumBytes !== undefined && descriptorMetadata.size > maximumBytes) {
          throw new Error(`Refusing to remove oversized native-host file: ${targetPath}`);
        }
        pinnedBytes = await handle.readFile();
      } finally {
        await handle.close();
      }
      if (
        descriptorMetadata.isFile() &&
        descriptorMetadata.dev === pinnedMetadata.dev &&
        descriptorMetadata.ino === pinnedMetadata.ino
      ) {
        validate(pinnedBytes, descriptorMetadata);

        await afterPin?.();
        await rename(targetPath, movedPath);
        moved = true;
        const movedMetadata = await lstat(movedPath);
        const samePinnedFile =
          movedMetadata.isFile() &&
          movedMetadata.dev === descriptorMetadata.dev &&
          movedMetadata.ino === descriptorMetadata.ino;

        if (samePinnedFile) {
          const finalBytes = await readFile(movedPath);
          if (finalBytes.equals(pinnedBytes)) {
            await unlink(movedPath);
            moved = false;
            result = "removed";
          } else {
            await restoreMovedFile(targetPath, movedPath);
            moved = false;
          }
        } else {
          await restoreMovedFile(targetPath, movedPath);
          moved = false;
        }
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") operationError = error;
  } finally {
    const cleanupErrors: unknown[] = [];
    if (moved) {
      await restoreMovedFile(targetPath, movedPath).catch((error: unknown) => {
        cleanupErrors.push(error);
      });
    }
    await unlink(pinnedPath).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") cleanupErrors.push(error);
    });
    if (cleanupErrors.length > 0) {
      cleanupError = new AggregateError(
        operationError === undefined ? cleanupErrors : [operationError, ...cleanupErrors],
        `TabGrant could not safely finish native-host manifest cleanup. Preserved recovery file, if any: ${movedPath}`,
      );
    }
  }
  if (cleanupError !== undefined) throw cleanupError;
  if (operationError !== undefined) {
    if (operationError instanceof Error) throw operationError;
    throw new Error("TabGrant native-host manifest cleanup failed.", { cause: operationError });
  }
  return result;
}

export function nativeManifestPath(browser: BrowserChannel): string {
  const browserDirectory = browserConfigDirectory(browser);
  return join(browserDirectory, "NativeMessagingHosts", `${NATIVE_HOST_NAME}.json`);
}

function browserConfigDirectory(browser: BrowserChannel): string {
  if (platform() === "darwin") {
    const directories: Record<BrowserChannel, string> = {
      chrome: join(homedir(), "Library", "Application Support", "Google", "Chrome"),
      "chrome-for-testing": join(
        homedir(),
        "Library",
        "Application Support",
        "Google",
        "ChromeForTesting",
      ),
      chromium: join(homedir(), "Library", "Application Support", "Chromium"),
      edge: join(homedir(), "Library", "Application Support", "Microsoft Edge"),
      brave: join(homedir(), "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
    };
    return directories[browser];
  }
  if (platform() === "linux") {
    const configRoot = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
    const directories: Record<BrowserChannel, string> = {
      chrome: join(configRoot, "google-chrome"),
      "chrome-for-testing": join(configRoot, "google-chrome-for-testing"),
      chromium: join(configRoot, "chromium"),
      edge: join(configRoot, "microsoft-edge"),
      brave: join(configRoot, "BraveSoftware", "Brave-Browser"),
    };
    return directories[browser];
  }
  throw new Error(
    "Native host installation is currently supported on macOS and Linux. Windows is tracked for v0.3.",
  );
}

function defaultNativeHostPath(): string {
  return fileURLToPath(new URL("./native-host-entry.js", import.meta.url));
}

function isOwnedManifest(parsed: Partial<NativeHostManifest>): parsed is NativeHostManifest {
  return (
    parsed.name === NATIVE_HOST_NAME &&
    parsed.description === MANIFEST_DESCRIPTION &&
    parsed.type === "stdio" &&
    typeof parsed.path === "string" &&
    resolve(parsed.path) === parsed.path &&
    Array.isArray(parsed.allowed_origins) &&
    parsed.allowed_origins.length === 1 &&
    typeof parsed.allowed_origins[0] === "string" &&
    /^chrome-extension:\/\/[a-p]{32}\/$/.test(parsed.allowed_origins[0])
  );
}

async function restoreMovedFile(targetPath: string, movedPath: string): Promise<void> {
  try {
    await link(movedPath, targetPath);
    await unlink(movedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `A native-host manifest changed during cleanup. The replacement remains at ${targetPath}; the inspected manifest is preserved at ${movedPath}.`,
        { cause: error },
      );
    }
    throw error;
  }
}

class FileMismatchError extends Error {}
