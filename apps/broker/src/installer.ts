import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, link, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, join, resolve } from "node:path";
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

interface NativeHostManifest {
  readonly name: typeof NATIVE_HOST_NAME;
  readonly description: string;
  readonly path: string;
  readonly type: "stdio";
  readonly allowed_origins: [string];
}

const MANIFEST_DESCRIPTION = "TabGrant local capability broker bridge";

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

export async function installNativeHost(options: InstallOptions): Promise<InstallResult> {
  const extensionId = ExtensionIdSchema.parse(options.extensionId);
  const browser = BrowserChannelSchema.parse(options.browser);
  const nativeHostPath = resolve(options.hostPath ?? defaultNativeHostPath());
  const hostMetadata = await lstat(nativeHostPath);
  if (!hostMetadata.isFile() || hostMetadata.isSymbolicLink()) {
    throw new Error(`Native host is not a regular file: ${nativeHostPath}`);
  }
  if (typeof process.getuid === "function" && hostMetadata.uid !== process.getuid()) {
    throw new Error(`Refusing native host owned by another user: ${nativeHostPath}`);
  }
  await chmod(nativeHostPath, 0o755);

  const manifestPath = nativeManifestPath(browser);
  const manifestDirectory = dirname(manifestPath);
  await mkdir(manifestDirectory, { recursive: true, mode: 0o700 });
  const directoryMetadata = await lstat(manifestDirectory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error(`Refusing insecure native-host manifest directory: ${manifestDirectory}`);
  }
  if (typeof process.getuid === "function" && directoryMetadata.uid !== process.getuid()) {
    throw new Error(`Refusing native-host directory owned by another user: ${manifestDirectory}`);
  }
  if (platform() !== "win32") await chmod(manifestDirectory, 0o700);
  const manifest: NativeHostManifest = {
    name: NATIVE_HOST_NAME,
    description: MANIFEST_DESCRIPTION,
    path: nativeHostPath,
    type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`],
  };
  await writeFileCreateOnly(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifestPath, nativeHostPath, extensionId, browser };
}

export async function uninstallNativeHost(
  browser: BrowserChannel,
): Promise<{ removed: boolean; manifestPath: string }> {
  const manifestPath = nativeManifestPath(BrowserChannelSchema.parse(browser));
  const removal = await removeFileIfMatching(manifestPath, (contents) => {
    let parsed: Partial<NativeHostManifest>;
    try {
      parsed = JSON.parse(contents.toString("utf8")) as Partial<NativeHostManifest>;
    } catch {
      throw new Error(`Refusing to remove a malformed native-host manifest: ${manifestPath}`);
    }
    if (!isOwnedManifest(parsed)) {
      throw new Error(`Refusing to remove a manifest not owned by TabGrant: ${manifestPath}`);
    }
  });
  if (removal === "missing") return { removed: false, manifestPath };
  if (removal === "changed") {
    throw new Error(`Refusing to remove a native-host manifest that changed: ${manifestPath}`);
  }
  return { removed: true, manifestPath };
}

/**
 * Publishes a file without ever replacing an existing path. The hard-link step is
 * atomic on supported filesystems and fails with EEXIST if another installer won.
 */
export async function writeFileCreateOnly(
  destinationPath: string,
  contents: string,
): Promise<void> {
  const temporaryPath = `${destinationPath}.${process.pid}.${randomUUID()}.tmp`;
  let handle;
  let published = false;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(contents, "utf8");
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
  validate: (contents: Buffer) => void,
  afterPin?: () => Promise<void>,
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
      let descriptorMetadata;
      try {
        [pinnedBytes, descriptorMetadata] = await Promise.all([handle.readFile(), handle.stat()]);
      } finally {
        await handle.close();
      }
      if (descriptorMetadata.isFile()) {
        validate(pinnedBytes);

        await afterPin?.();
        await rename(targetPath, movedPath);
        moved = true;
        const movedMetadata = await lstat(movedPath);
        const samePinnedFile =
          movedMetadata.isFile() &&
          movedMetadata.dev === pinnedMetadata.dev &&
          movedMetadata.ino === pinnedMetadata.ino;

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

function isOwnedManifest(parsed: Partial<NativeHostManifest>): boolean {
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
