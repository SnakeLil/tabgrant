import { mkdtemp, readFile, readdir, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { removeFileIfUnchanged, writeFileCreateOnly } from "../src/installer.js";

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

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "tabgrant-installer-test-"));
  temporaryDirectories.push(directory);
  return directory;
}
