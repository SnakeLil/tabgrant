import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";

const KillSwitchMarkerSchema = z
  .object({
    version: z.literal(1),
    activatedAt: z.string().datetime({ offset: true }),
  })
  .strict();

export interface KillSwitchStatus {
  readonly active: boolean;
  readonly activatedAt?: string;
}

export async function readKillSwitch(path: string): Promise<KillSwitchStatus> {
  let handle;
  try {
    handle = await open(
      path,
      process.platform === "win32" ? constants.O_RDONLY : constants.O_RDONLY | constants.O_NOFOLLOW,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { active: false };
    throw error;
  }

  try {
    const metadata = await handle.stat();
    assertPrivateRegularFile(path, metadata);
    const marker = KillSwitchMarkerSchema.parse(
      JSON.parse(await handle.readFile({ encoding: "utf8" })) as unknown,
    );
    return { active: true, activatedAt: marker.activatedAt };
  } finally {
    await handle.close();
  }
}

export async function assertKillSwitchDisabled(path: string): Promise<void> {
  const status = await readKillSwitch(path);
  if (status.active) {
    throw new Error(
      `TabGrant is disabled by its persistent kill switch (${status.activatedAt ?? "unknown time"}). Run \`tabgrant enable --confirm\` in a local terminal to re-enable it.`,
    );
  }
}

export async function activateKillSwitch(path: string, now = Date.now()): Promise<void> {
  await ensurePrivateDirectory(dirname(path));
  const existing = await readKillSwitch(path);
  if (existing.active) return;

  const temporaryPath = `${path}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const handle = await open(temporaryPath, "wx", 0o600);
  try {
    await handle.writeFile(
      `${JSON.stringify({ version: 1, activatedAt: new Date(now).toISOString() })}\n`,
      "utf8",
    );
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporaryPath, path);
  await chmod(path, 0o600);
}

export async function clearKillSwitch(path: string): Promise<{ cleared: boolean }> {
  const status = await readKillSwitch(path);
  if (!status.active) return { cleared: false };
  await unlink(path);
  return { cleared: true };
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Refusing insecure TabGrant directory: ${path}`);
  }
  assertOwnedByCurrentUser(path, metadata.uid);
  await chmod(path, 0o700);
}

function assertPrivateRegularFile(
  path: string,
  metadata: { isFile(): boolean; mode: number; uid: number },
): void {
  if (!metadata.isFile()) throw new Error(`Refusing non-regular TabGrant file: ${path}`);
  assertOwnedByCurrentUser(path, metadata.uid);
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw new Error(`Refusing permissive TabGrant file: ${path}`);
  }
}

function assertOwnedByCurrentUser(path: string, uid: number): void {
  if (typeof process.getuid === "function" && uid !== process.getuid()) {
    throw new Error(`Refusing TabGrant path owned by another user: ${path}`);
  }
}
