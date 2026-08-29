import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  activateKillSwitch,
  assertKillSwitchDisabled,
  clearKillSwitch,
  readKillSwitch,
} from "../src/kill-switch.js";

describe("persistent kill switch", () => {
  const directories: string[] = [];

  afterEach(async () => {
    await Promise.allSettled(
      directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
    );
  });

  it("persists until an explicit enable clears the marker", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "disabled.json");

    expect(await readKillSwitch(path)).toEqual({ active: false });
    await activateKillSwitch(path, Date.UTC(2026, 7, 30, 0, 0, 0));
    await expect(assertKillSwitchDisabled(path)).rejects.toThrow(/tabgrant enable --confirm/i);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      version: 1,
      activatedAt: "2026-08-30T00:00:00.000Z",
    });
    expect(await clearKillSwitch(path)).toEqual({ cleared: true });
    await expect(assertKillSwitchDisabled(path)).resolves.toBeUndefined();
  });

  it.runIf(process.platform !== "win32")(
    "fails closed for permissive or symlinked markers",
    async () => {
      const directory = await temporaryDirectory();
      const permissive = join(directory, "permissive.json");
      await writeFile(
        permissive,
        `${JSON.stringify({ version: 1, activatedAt: "2026-08-30T00:00:00.000Z" })}\n`,
        { mode: 0o600 },
      );
      await chmod(permissive, 0o644);
      await expect(readKillSwitch(permissive)).rejects.toThrow(/permissive/i);

      const link = join(directory, "link.json");
      await symlink(permissive, link);
      await expect(readKillSwitch(link)).rejects.toThrow();
    },
  );

  async function temporaryDirectory(): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), "tabgrant-kill-test-"));
    directories.push(directory);
    return directory;
  }
});
