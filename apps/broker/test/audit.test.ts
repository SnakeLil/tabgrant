import { randomBytes } from "node:crypto";
import {
  chmod,
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
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLogger } from "../src/audit.js";

const DAY_MS = 24 * 60 * 60 * 1_000;

describe("audit logger", () => {
  const directories: string[] = [];

  afterEach(async () => {
    await Promise.all(
      directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
    );
  });

  async function fixture(): Promise<{ path: string; key: Buffer }> {
    const directory = await mkdtemp(join(tmpdir(), "tabgrant-audit-"));
    directories.push(directory);
    return { path: join(directory, "audit.jsonl"), key: randomBytes(32) };
  }

  it("continues a verified HMAC chain across startup and keeps the file private", async () => {
    const { path, key } = await fixture();
    const startedAt = Date.UTC(2026, 0, 1);
    const first = new AuditLogger(path, key);
    await first.initialize(startedAt);
    await first.record(
      { event: "access.requested", outcome: "info", clientId: "codex" },
      startedAt,
    );

    const second = new AuditLogger(path, key);
    await second.initialize(startedAt + DAY_MS);
    await second.record(
      { event: "access.granted", outcome: "allowed", taskId: "task-1" },
      startedAt + DAY_MS,
    );

    const lines = parseLines(await readFile(path, "utf8"));
    expect(lines).toHaveLength(2);
    expect(lines[1]?.previousHash).toBe(lines[0]?.hash);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(manifestPath(path))).mode & 0o777).toBe(0o600);
    await expect(
      new AuditLogger(path, key).initialize(startedAt + 2 * DAY_MS),
    ).resolves.toBeUndefined();
  });

  it("fails closed when the signed manifest is missing for an existing segment", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(now);
    await logger.record({ event: "manifest.required", outcome: "info" }, now);

    await unlink(manifestPath(path));
    await expect(new AuditLogger(path, key).initialize(now + 1)).rejects.toThrow(
      /signed manifest is missing/,
    );
  });

  it("fails closed when a signed manifest field is tampered with", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(now);
    await logger.record({ event: "manifest.signed", outcome: "info" }, now);

    const manifest = JSON.parse(await readFile(manifestPath(path), "utf8")) as Record<
      string,
      unknown
    >;
    manifest.generation = Number(manifest.generation) + 1;
    await writeFile(manifestPath(path), `${JSON.stringify(manifest)}\n`, { mode: 0o600 });

    await expect(new AuditLogger(path, key).initialize(now + 1)).rejects.toThrow(
      /manifest HMAC mismatch/,
    );
  });

  it("fails closed when a complete trailing record is removed", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(now);
    await logger.record({ event: "tail.first", outcome: "info" }, now);
    await logger.record({ event: "tail.second", outcome: "info" }, now + 1);

    const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
    await writeFile(path, `${lines[0]}\n`, { mode: 0o600 });

    await expect(new AuditLogger(path, key).initialize(now + 2)).rejects.toThrow(
      /does not match its signed manifest/,
    );
  });

  it("fails closed on the append-before-manifest crash boundary", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(now);
    await logger.record({ event: "crash.committed", outcome: "info" }, now);
    const staleManifest = await readFile(manifestPath(path));
    await logger.record({ event: "crash.unanchored", outcome: "info" }, now + 1);

    await writeFile(manifestPath(path), staleManifest, { mode: 0o600 });
    await expect(new AuditLogger(path, key).initialize(now + 2)).rejects.toThrow(
      /does not match its signed manifest/,
    );
  });

  it("fails closed when a signed field is tampered with", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(now);
    await logger.record({ event: "access.granted", outcome: "allowed" }, now);
    const line = JSON.parse((await readFile(path, "utf8")).trim()) as Record<string, unknown>;
    line.outcome = "denied";
    await writeFile(path, `${JSON.stringify(line)}\n`, { mode: 0o600 });

    await expect(new AuditLogger(path, key).initialize(now + 1)).rejects.toThrow(/HMAC mismatch/);
  });

  it.each([
    ["truncated JSON", '{"event":"access.requested"'],
    ["missing record delimiter", '{"event":"access.requested","outcome":"info"}'],
    ["unknown field", '{"event":"x","outcome":"info","unexpected":true}\n'],
    ["blank record", "\n"],
  ])("fails closed for %s", async (_label, contents) => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(now);
    await logger.record({ event: "format.valid", outcome: "info" }, now);
    await writeFile(path, contents, { mode: 0o600 });
    await expect(new AuditLogger(path, key).initialize(now + 1)).rejects.toThrow(
      /Audit integrity verification failed/,
    );
  });

  it("rotates a long-running segment from its first record time during record", async () => {
    const { path, key } = await fixture();
    const startedAt = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(startedAt);
    await logger.record({ event: "segment.started", outcome: "info" }, startedAt);
    await logger.record({ event: "segment.active", outcome: "info" }, startedAt + 29 * DAY_MS);
    await logger.record({ event: "segment.rotated", outcome: "info" }, startedAt + 30 * DAY_MS);

    const lines = parseLines(await readFile(path, "utf8"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      event: "segment.rotated",
      previousHash: "0".repeat(64),
    });
    expect(await auditSegmentPaths(path)).toEqual([path]);
  });

  it("rotates a verified expired segment during startup", async () => {
    const { path, key } = await fixture();
    const startedAt = Date.UTC(2026, 0, 1);
    const first = new AuditLogger(path, key);
    await first.initialize(startedAt);
    await first.record({ event: "segment.started", outcome: "info" }, startedAt);

    const restarted = new AuditLogger(path, key);
    await restarted.initialize(startedAt + 30 * DAY_MS);
    await restarted.record(
      { event: "segment.restarted", outcome: "info" },
      startedAt + 30 * DAY_MS,
    );

    expect(parseLines(await readFile(path, "utf8"))).toEqual([
      expect.objectContaining({
        event: "segment.restarted",
        previousHash: "0".repeat(64),
      }),
    ]);
    expect(await auditSegmentPaths(path)).toEqual([path]);
  });

  it("purges an expired retained segment while preserving a newer active segment", async () => {
    const { path, key } = await fixture();
    const startedAt = Date.UTC(2026, 0, 1);
    const options = { segmentMaxBytes: 1_000, totalMaxBytes: 3_000 };
    const logger = new AuditLogger(path, key, options);
    await logger.initialize(startedAt);
    await logger.record(
      {
        event: "retention.old",
        outcome: "info",
        origin: `https://example.test/${"x".repeat(400)}`,
      },
      startedAt,
    );
    await logger.record(
      {
        event: "retention.current",
        outcome: "info",
        origin: `https://example.test/${"y".repeat(400)}`,
      },
      startedAt + 15 * DAY_MS,
    );
    expect(await auditSegmentPaths(path)).toEqual([path, `${path}.1`]);

    await logger.record({ event: "retention.pruned", outcome: "info" }, startedAt + 30 * DAY_MS);

    expect(await auditSegmentPaths(path)).toEqual([path]);
    expect(parseLines(await readFile(path, "utf8")).map((record) => record.event)).toEqual([
      "retention.current",
      "retention.pruned",
    ]);
  });

  it("validates an expired segment before rotating it at startup", async () => {
    const { path, key } = await fixture();
    const startedAt = Date.UTC(2026, 0, 1);
    const logger = new AuditLogger(path, key);
    await logger.initialize(startedAt);
    await logger.record({ event: "segment.started", outcome: "info" }, startedAt);

    const tampered = (await readFile(path, "utf8")).replace("segment.started", "segment.changed");
    await writeFile(path, tampered, { mode: 0o600 });
    await expect(new AuditLogger(path, key).initialize(startedAt + 31 * DAY_MS)).rejects.toThrow(
      /HMAC mismatch/,
    );
  });

  it("bounds retained segments and verifies them again after restart", async () => {
    const { path, key } = await fixture();
    const startedAt = Date.UTC(2026, 0, 1);
    const options = { segmentMaxBytes: 900, totalMaxBytes: 2_700 };
    const logger = new AuditLogger(path, key, options);
    await logger.initialize(startedAt);

    for (let index = 0; index < 12; index += 1) {
      await logger.record(
        {
          event: `bounded.${index}`,
          outcome: "info",
          origin: `https://example.test/${"x".repeat(400)}`,
        },
        startedAt + index,
      );
    }

    const paths = await auditSegmentPaths(path);
    expect(paths).toHaveLength(3);
    const metadata = await Promise.all(paths.map((segmentPath) => stat(segmentPath)));
    expect(metadata.every((entry) => entry.size <= options.segmentMaxBytes)).toBe(true);
    expect(metadata.reduce((total, entry) => total + entry.size, 0)).toBeLessThanOrEqual(
      options.totalMaxBytes,
    );
    if (process.platform !== "win32") {
      expect(metadata.every((entry) => (entry.mode & 0o777) === 0o600)).toBe(true);
    }

    const restarted = new AuditLogger(path, key, options);
    await restarted.initialize(startedAt + DAY_MS);
    await expect(
      restarted.record({ event: "bounded.restarted", outcome: "info" }, startedAt + DAY_MS),
    ).resolves.toBeUndefined();
    const restartedMetadata = await Promise.all(
      (await auditSegmentPaths(path)).map((segmentPath) => stat(segmentPath)),
    );
    expect(restartedMetadata.reduce((total, entry) => total + entry.size, 0)).toBeLessThanOrEqual(
      options.totalMaxBytes,
    );
  });

  it("fails closed when a retained segment is tampered with", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const options = { segmentMaxBytes: 700, totalMaxBytes: 2_100 };
    const logger = new AuditLogger(path, key, options);
    await logger.initialize(now);
    for (let index = 0; index < 3; index += 1) {
      await logger.record(
        {
          event: `retained.${index}`,
          outcome: "info",
          origin: `https://example.test/${"x".repeat(300)}`,
        },
        now + index,
      );
    }

    const retainedPath = `${path}.1`;
    const tampered = (await readFile(retainedPath, "utf8")).replace("retained.1", "retained.x");
    await writeFile(retainedPath, tampered, { mode: 0o600 });

    await expect(new AuditLogger(path, key, options).initialize(now + DAY_MS)).rejects.toThrow(
      /HMAC mismatch/,
    );
  });

  it("fails closed when a retained segment is deleted", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const options = { segmentMaxBytes: 700, totalMaxBytes: 2_100 };
    const logger = new AuditLogger(path, key, options);
    await logger.initialize(now);
    for (let index = 0; index < 3; index += 1) {
      await logger.record(
        {
          event: `deleted.${index}`,
          outcome: "info",
          origin: `https://example.test/${"x".repeat(300)}`,
        },
        now + index,
      );
    }

    await unlink(`${path}.1`);
    await expect(new AuditLogger(path, key, options).initialize(now + DAY_MS)).rejects.toThrow(
      /segment set does not match disk/,
    );
  });

  it("fails closed when retained segments are reordered", async () => {
    const { path, key } = await fixture();
    const now = Date.UTC(2026, 0, 1);
    const options = { segmentMaxBytes: 700, totalMaxBytes: 2_100 };
    const logger = new AuditLogger(path, key, options);
    await logger.initialize(now);
    for (let index = 0; index < 5; index += 1) {
      await logger.record(
        {
          event: `reordered.${index}`,
          outcome: "info",
          origin: `https://example.test/${"x".repeat(300)}`,
        },
        now + index,
      );
    }
    expect(await auditSegmentPaths(path)).toEqual([path, `${path}.1`, `${path}.2`]);

    const first = await readFile(`${path}.1`);
    const second = await readFile(`${path}.2`);
    await writeFile(`${path}.1`, second, { mode: 0o600 });
    await writeFile(`${path}.2`, first, { mode: 0o600 });

    await expect(new AuditLogger(path, key, options).initialize(now + DAY_MS)).rejects.toThrow(
      /does not match its signed manifest/,
    );
  });

  it.runIf(process.platform !== "win32")(
    "rejects permissive and symlinked audit segments",
    async () => {
      const { path, key } = await fixture();
      const now = Date.UTC(2026, 0, 1);
      const logger = new AuditLogger(path, key);
      await logger.initialize(now);
      await logger.record({ event: "segment.started", outcome: "info" }, now);
      await chmod(path, 0o644);
      await expect(new AuditLogger(path, key).initialize(now + 1)).rejects.toThrow(/permissive/i);

      const link = `${path}.link`;
      await symlink(path, link);
      await expect(new AuditLogger(link, key).initialize(now + 1)).rejects.toThrow();
    },
  );
});

function parseLines(contents: string): Array<Record<string, unknown>> {
  return contents
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function auditSegmentPaths(path: string): Promise<string[]> {
  const directory = dirname(path);
  const filename = basename(path);
  const names = await readdir(directory);
  return names
    .filter(
      (name) => name === filename || new RegExp(`^${escapeRegex(filename)}\\.\\d+$`).test(name),
    )
    .sort()
    .map((name) => join(directory, name));
}

function manifestPath(path: string): string {
  return `${path}.manifest.json`;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
