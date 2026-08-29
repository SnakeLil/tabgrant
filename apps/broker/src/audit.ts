import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { z } from "zod";

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const INITIAL_HASH = "0".repeat(64);
const RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;
const AUDIT_MANIFEST_FORMAT = "tabgrant.audit-manifest";
const AUDIT_MANIFEST_VERSION = 1;
const AUDIT_MANIFEST_MAX_BYTES = 16_384;
const MANIFEST_HMAC_DOMAIN = "tabgrant:audit-manifest:v1\0";
export const AUDIT_SEGMENT_MAX_BYTES = 1_048_576;
export const AUDIT_TOTAL_MAX_BYTES = 4_194_304;
export const AUDIT_MAX_SEGMENTS = 4;

const AuditRecordSchema = z
  .object({
    event: z.string().min(1).max(128),
    outcome: z.enum(["allowed", "denied", "info"]),
    clientId: z.string().min(1).max(128).optional(),
    taskId: z.string().min(1).max(128).optional(),
    leaseId: z.string().min(1).max(128).optional(),
    origin: z.string().min(1).max(2_048).optional(),
    method: z.string().min(1).max(96).optional(),
    reasonCode: z.string().min(1).max(128).optional(),
  })
  .strict();

const TimestampSchema = z.string().refine(
  (value) => {
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
  },
  { message: "Expected a canonical ISO timestamp." },
);

const PersistedAuditRecordSchema = AuditRecordSchema.extend({
  timestamp: TimestampSchema,
  previousHash: z.string().regex(HASH_PATTERN),
  hash: z.string().regex(HASH_PATTERN),
}).strict();

const AuditManifestSegmentSchema = z
  .object({
    index: z
      .number()
      .int()
      .min(0)
      .max(AUDIT_MAX_SEGMENTS - 1),
    file: z.string().min(1).max(255),
    createdAt: TimestampSchema,
    bytes: z.number().int().positive().max(AUDIT_SEGMENT_MAX_BYTES),
    recordCount: z.number().int().positive(),
    firstHash: z.string().regex(HASH_PATTERN),
    lastHash: z.string().regex(HASH_PATTERN),
    sha256: z.string().regex(HASH_PATTERN),
  })
  .strict();

const UnsignedAuditManifestSchema = z
  .object({
    format: z.literal(AUDIT_MANIFEST_FORMAT),
    version: z.literal(AUDIT_MANIFEST_VERSION),
    generation: z.number().int().nonnegative().safe(),
    segments: z.array(AuditManifestSegmentSchema).max(AUDIT_MAX_SEGMENTS),
  })
  .strict();

const AuditManifestSchema = UnsignedAuditManifestSchema.extend({
  hmac: z.string().regex(HASH_PATTERN),
}).strict();

export type AuditRecord = z.infer<typeof AuditRecordSchema>;
type PersistedAuditRecord = z.infer<typeof PersistedAuditRecordSchema>;
type UnsignedAuditRecord = Omit<PersistedAuditRecord, "hash">;
type AuditManifestSegment = z.infer<typeof AuditManifestSegmentSchema>;
type UnsignedAuditManifest = z.infer<typeof UnsignedAuditManifestSchema>;
type AuditManifest = z.infer<typeof AuditManifestSchema>;

export interface AuditLoggerOptions {
  readonly segmentMaxBytes?: number;
  readonly totalMaxBytes?: number;
}

export class AuditLogger {
  private readonly key: Buffer;
  private readonly segmentMaxBytes: number;
  private readonly totalMaxBytes: number;
  private readonly maxSegments: number;
  private previousHash = INITIAL_HASH;
  private segmentCreatedAt: number | undefined;
  private segmentBytes = 0;
  private manifestGeneration = 0;
  private readonly segments = new Map<number, AuditManifestSegment>();
  private initialized = false;
  private poisoned = false;
  private writeQueue = Promise.resolve();

  public constructor(
    private readonly path: string,
    key: Buffer | Uint8Array,
    options: AuditLoggerOptions = {},
  ) {
    if (key.byteLength < 32) {
      throw new Error("The audit HMAC key must contain at least 32 bytes.");
    }
    this.key = Buffer.from(key);
    this.segmentMaxBytes = boundedByteLimit(
      "audit segment",
      options.segmentMaxBytes ?? AUDIT_SEGMENT_MAX_BYTES,
      AUDIT_SEGMENT_MAX_BYTES,
    );
    this.totalMaxBytes = boundedByteLimit(
      "audit total",
      options.totalMaxBytes ?? AUDIT_TOTAL_MAX_BYTES,
      AUDIT_TOTAL_MAX_BYTES,
    );
    if (this.totalMaxBytes < this.segmentMaxBytes * 2) {
      throw new Error("The audit total byte limit must hold at least two segments.");
    }
    this.maxSegments = Math.min(
      AUDIT_MAX_SEGMENTS,
      Math.floor(this.totalMaxBytes / this.segmentMaxBytes),
    );
  }

  public async initialize(now = Date.now()): Promise<void> {
    if (this.initialized) {
      throw new Error("The audit logger is already initialized.");
    }
    await ensurePrivateDirectory(dirname(this.path));

    const discoveredIndices = await this.discoverSegmentIndices();
    const manifest = await this.loadAndVerifyManifest();
    if (manifest === undefined) {
      if (discoveredIndices.length > 0) {
        throw new Error(
          "Audit integrity verification failed: signed manifest is missing for existing segments.",
        );
      }
      await this.persistManifest();
      this.initialized = true;
      return;
    }

    this.validateManifestLayout(manifest, discoveredIndices);
    this.manifestGeneration = manifest.generation;
    let totalBytes = 0;
    for (const expected of manifest.segments) {
      const loaded = await this.loadAndVerifySegment(this.segmentPath(expected.index));
      if (loaded === undefined) {
        throw new Error(`Audit integrity verification failed: missing segment ${expected.file}.`);
      }
      const actual = manifestSegment(expected.index, this.segmentPath(expected.index), loaded);
      if (!manifestSegmentsEqual(actual, expected)) {
        throw new Error(
          `Audit integrity verification failed: segment ${expected.file} does not match its signed manifest.`,
        );
      }
      this.segments.set(expected.index, actual);
      totalBytes += actual.bytes;
      if (totalBytes > this.totalMaxBytes) {
        throw new Error("Audit integrity verification failed: total size limit exceeded.");
      }
      if (expected.index === 0) {
        this.segmentCreatedAt = Date.parse(actual.createdAt);
        this.previousHash = actual.lastHash;
        this.segmentBytes = actual.bytes;
      }
    }

    await this.removeExpiredSegments(now);
    this.initialized = true;
  }

  public record(record: AuditRecord, now = Date.now()): Promise<void> {
    const operation = async (): Promise<void> => {
      if (!this.initialized) {
        throw new Error("The audit logger must be initialized before recording events.");
      }
      if (this.poisoned) {
        throw new Error("Audit logger is unavailable after a failed atomic manifest update.");
      }
      const validated = AuditRecordSchema.parse(record);
      await this.removeExpiredSegments(now);

      let serialized = this.serializeRecord(validated, now);
      if (serialized.line.byteLength > this.segmentMaxBytes) {
        throw new Error("Audit record exceeds the segment byte limit.");
      }
      if (
        this.segmentBytes > 0 &&
        this.segmentBytes + serialized.line.byteLength > this.segmentMaxBytes
      ) {
        await this.rotateCurrentSegment();
        serialized = this.serializeRecord(validated, now);
      }
      const flags =
        constants.O_APPEND |
        constants.O_CREAT |
        constants.O_WRONLY |
        (process.platform === "win32" ? 0 : constants.O_NOFOLLOW);
      const handle = await open(this.path, flags, 0o600);
      try {
        const metadata = await handle.stat();
        assertPrivateRegularFile(this.path, metadata);
        if (metadata.size !== this.segmentBytes) {
          throw new Error("Audit integrity verification failed: active segment size changed.");
        }
        if (metadata.size + serialized.line.byteLength > this.segmentMaxBytes) {
          throw new Error("Audit segment byte limit exceeded.");
        }
        await handle.appendFile(serialized.line);
        await handle.sync();
        await handle.chmod(0o600);
      } finally {
        await handle.close();
      }

      try {
        this.segmentCreatedAt ??= now;
        this.segmentBytes += serialized.line.byteLength;
        this.previousHash = serialized.hash;
        const previous = this.segments.get(0);
        this.segments.set(0, {
          index: 0,
          file: basename(this.path),
          createdAt: new Date(this.segmentCreatedAt).toISOString(),
          bytes: this.segmentBytes,
          recordCount: (previous?.recordCount ?? 0) + 1,
          firstHash: previous?.firstHash ?? serialized.hash,
          lastHash: serialized.hash,
          sha256: await fileSha256(this.path),
        });
        await this.persistManifest();
      } catch (error) {
        throw this.failAfterMutation(error);
      }
    };
    this.writeQueue = this.writeQueue.then(operation, operation);
    return this.writeQueue;
  }

  private verifySegment(serialized: string): PersistedAuditRecord[] {
    if (serialized.length === 0 || !serialized.endsWith("\n")) {
      throw new Error("Audit integrity verification failed: empty or truncated segment.");
    }
    const lines = serialized.slice(0, -1).split("\n");
    if (lines.some((line) => line.length === 0)) {
      throw new Error("Audit integrity verification failed: blank record.");
    }

    const records: PersistedAuditRecord[] = [];
    let expectedPreviousHash = INITIAL_HASH;
    for (const line of lines) {
      let candidate: unknown;
      try {
        candidate = JSON.parse(line) as unknown;
      } catch {
        throw new Error("Audit integrity verification failed: malformed JSON record.");
      }
      const parsed = PersistedAuditRecordSchema.safeParse(candidate);
      if (!parsed.success) {
        throw new Error("Audit integrity verification failed: invalid record structure.");
      }
      if (parsed.data.previousHash !== expectedPreviousHash) {
        throw new Error("Audit integrity verification failed: broken hash chain.");
      }
      const expectedHash = this.signRecord(unsignedRecordFromPersisted(parsed.data));
      if (!hashesEqual(parsed.data.hash, expectedHash)) {
        throw new Error("Audit integrity verification failed: record HMAC mismatch.");
      }
      records.push(parsed.data);
      expectedPreviousHash = parsed.data.hash;
    }
    return records;
  }

  private signRecord(record: UnsignedAuditRecord): string {
    return createHmac("sha256", this.key).update(JSON.stringify(record)).digest("hex");
  }

  private signManifest(manifest: UnsignedAuditManifest): string {
    return createHmac("sha256", this.key)
      .update(MANIFEST_HMAC_DOMAIN)
      .update(JSON.stringify(manifest))
      .digest("hex");
  }

  private serializeRecord(record: AuditRecord, now: number): { line: Buffer; hash: string } {
    const timestamp = new Date(now).toISOString();
    const unsigned = unsignedRecord(record, timestamp, this.previousHash);
    const persisted: PersistedAuditRecord = { ...unsigned, hash: this.signRecord(unsigned) };
    return { line: Buffer.from(`${JSON.stringify(persisted)}\n`, "utf8"), hash: persisted.hash };
  }

  private async loadAndVerifySegment(
    path: string,
  ): Promise<{ records: PersistedAuditRecord[]; bytes: number; sha256: string } | undefined> {
    const handle = await openPrivateFileIfPresent(path);
    if (handle === undefined) return undefined;
    try {
      const metadata = await handle.stat();
      assertPrivateRegularFile(path, metadata);
      if (metadata.size > this.segmentMaxBytes) {
        throw new Error("Audit integrity verification failed: segment size limit exceeded.");
      }
      const contents = await handle.readFile();
      const records = this.verifySegment(contents.toString("utf8"));
      await handle.chmod(0o600);
      return { records, bytes: metadata.size, sha256: sha256(contents) };
    } finally {
      await handle.close();
    }
  }

  private async loadAndVerifyManifest(): Promise<AuditManifest | undefined> {
    const path = this.manifestPath();
    const handle = await openPrivateFileIfPresent(path);
    if (handle === undefined) return undefined;
    try {
      const metadata = await handle.stat();
      assertPrivateRegularFile(path, metadata);
      if (metadata.size === 0 || metadata.size > AUDIT_MANIFEST_MAX_BYTES) {
        throw new Error("Audit integrity verification failed: invalid manifest size.");
      }
      const serialized = await handle.readFile({ encoding: "utf8" });
      if (!serialized.endsWith("\n")) {
        throw new Error("Audit integrity verification failed: truncated manifest.");
      }
      let candidate: unknown;
      try {
        candidate = JSON.parse(serialized.slice(0, -1)) as unknown;
      } catch {
        throw new Error("Audit integrity verification failed: malformed manifest JSON.");
      }
      const parsed = AuditManifestSchema.safeParse(candidate);
      if (!parsed.success) {
        throw new Error("Audit integrity verification failed: invalid manifest structure.");
      }
      const unsigned = unsignedManifest(parsed.data);
      if (!hashesEqual(parsed.data.hmac, this.signManifest(unsigned))) {
        throw new Error("Audit integrity verification failed: manifest HMAC mismatch.");
      }
      await handle.chmod(0o600);
      return parsed.data;
    } finally {
      await handle.close();
    }
  }

  private validateManifestLayout(manifest: AuditManifest, discoveredIndices: number[]): void {
    const expectedIndices = manifest.segments.map((segment) => segment.index);
    if (
      new Set(expectedIndices).size !== expectedIndices.length ||
      !expectedIndices.every(
        (index, position) => position === 0 || expectedIndices[position - 1]! < index,
      )
    ) {
      throw new Error("Audit integrity verification failed: manifest segment order is invalid.");
    }
    if (
      discoveredIndices.length !== expectedIndices.length ||
      discoveredIndices.some((index, position) => index !== expectedIndices[position])
    ) {
      throw new Error(
        "Audit integrity verification failed: manifest segment set does not match disk.",
      );
    }
    for (const segment of manifest.segments) {
      if (
        segment.index >= this.maxSegments ||
        segment.file !== basename(this.segmentPath(segment.index)) ||
        segment.bytes > this.segmentMaxBytes
      ) {
        throw new Error(
          "Audit integrity verification failed: manifest contains an invalid segment file.",
        );
      }
    }
  }

  private async discoverSegmentIndices(): Promise<number[]> {
    const directory = dirname(this.path);
    const filename = basename(this.path);
    const names = await readdir(directory);
    const indices: number[] = [];
    for (const name of names) {
      if (name === filename) {
        indices.push(0);
        continue;
      }
      if (!name.startsWith(`${filename}.`)) continue;
      const suffix = name.slice(filename.length + 1);
      if (!/^\d+$/.test(suffix)) continue;
      const index = Number(suffix);
      if (!Number.isSafeInteger(index) || index <= 0 || index >= this.maxSegments) {
        throw new Error(`Audit integrity verification failed: unexpected segment file ${name}.`);
      }
      indices.push(index);
    }
    return indices.sort((left, right) => left - right);
  }

  private async rotateCurrentSegment(): Promise<void> {
    if (this.segmentBytes === 0) {
      this.resetActiveSegment();
      return;
    }

    let mutated = false;
    try {
      for (let index = this.maxSegments - 1; index >= 1; index -= 1) {
        const destination = this.segmentPath(index);
        if (index === this.maxSegments - 1) {
          await unlinkIfExists(destination);
          this.segments.delete(index);
          mutated = true;
        }
        const source = this.segmentPath(index - 1);
        const sourceState = this.segments.get(index - 1);
        try {
          await rename(source, destination);
          mutated = true;
          if (sourceState === undefined) {
            throw new Error(
              `Audit integrity verification failed: segment metadata is missing for ${source}.`,
            );
          }
          this.segments.set(index, {
            ...sourceState,
            index,
            file: basename(destination),
          });
          this.segments.delete(index - 1);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          if (sourceState !== undefined || index === 1) {
            throw new Error("Audit integrity verification failed: active segment disappeared.", {
              cause: error,
            });
          }
        }
      }
      this.resetActiveSegment();
      await this.persistManifest();
    } catch (error) {
      if (mutated) throw this.failAfterMutation(error);
      throw error;
    }
  }

  private async removeExpiredSegments(now: number): Promise<void> {
    let changed = false;
    try {
      for (const [index, segment] of [...this.segments.entries()].sort(
        ([left], [right]) => right - left,
      )) {
        if (!segmentExpired(Date.parse(segment.createdAt), now)) continue;
        await unlink(this.segmentPath(index));
        this.segments.delete(index);
        changed = true;
        if (index === 0) this.resetActiveSegment();
      }
      if (changed) await this.persistManifest();
    } catch (error) {
      if (changed) throw this.failAfterMutation(error);
      throw error;
    }
  }

  private failAfterMutation(error: unknown): Error {
    this.poisoned = true;
    return new Error(
      "Audit manifest update failed after segment mutation; fail-closed restart required.",
      { cause: error },
    );
  }

  private async persistManifest(): Promise<void> {
    if (this.manifestGeneration >= Number.MAX_SAFE_INTEGER) {
      throw new Error("Audit manifest generation is exhausted.");
    }
    const unsigned: UnsignedAuditManifest = {
      format: AUDIT_MANIFEST_FORMAT,
      version: AUDIT_MANIFEST_VERSION,
      generation: this.manifestGeneration + 1,
      segments: [...this.segments.values()].sort((left, right) => left.index - right.index),
    };
    const manifest: AuditManifest = { ...unsigned, hmac: this.signManifest(unsigned) };
    const contents = Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8");
    if (contents.byteLength > AUDIT_MANIFEST_MAX_BYTES) {
      throw new Error("Audit manifest exceeds its byte limit.");
    }
    await atomicWritePrivateFile(this.manifestPath(), contents);
    this.manifestGeneration = unsigned.generation;
  }

  private segmentPath(index: number): string {
    return index === 0 ? this.path : `${this.path}.${index}`;
  }

  private manifestPath(): string {
    return `${this.path}.manifest.json`;
  }

  private resetActiveSegment(): void {
    this.previousHash = INITIAL_HASH;
    this.segmentCreatedAt = undefined;
    this.segmentBytes = 0;
  }
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Refusing insecure TabGrant audit directory: ${path}`);
  }
  assertOwnedByCurrentUser(path, metadata.uid);
  await chmod(path, 0o700);
}

async function openPrivateFileIfPresent(path: string) {
  try {
    return await open(
      path,
      process.platform === "win32" ? constants.O_RDONLY : constants.O_RDONLY | constants.O_NOFOLLOW,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function atomicWritePrivateFile(path: string, contents: Buffer): Promise<void> {
  const temporaryPath = `${path}.tmp-${process.pid}-${randomBytes(16).toString("hex")}`;
  const flags =
    constants.O_CREAT |
    constants.O_EXCL |
    constants.O_WRONLY |
    (process.platform === "win32" ? 0 : constants.O_NOFOLLOW);
  let handle;
  try {
    handle = await open(temporaryPath, flags, 0o600);
    const metadata = await handle.stat();
    assertPrivateRegularFile(temporaryPath, metadata);
    await handle.writeFile(contents);
    await handle.sync();
    await handle.chmod(0o600);
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, path);
    if (process.platform !== "win32") {
      const directoryHandle = await open(dirname(path), constants.O_RDONLY);
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    }
  } catch (error) {
    await handle?.close();
    await unlinkIfExists(temporaryPath);
    throw error;
  }
}

function assertPrivateRegularFile(
  path: string,
  metadata: { isFile(): boolean; mode: number; uid: number },
): void {
  if (!metadata.isFile()) throw new Error(`Refusing non-regular TabGrant audit file: ${path}`);
  assertOwnedByCurrentUser(path, metadata.uid);
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw new Error(`Refusing permissive TabGrant audit file: ${path}`);
  }
}

function assertOwnedByCurrentUser(path: string, uid: number): void {
  if (typeof process.getuid === "function" && uid !== process.getuid()) {
    throw new Error(`Refusing TabGrant path owned by another user: ${path}`);
  }
}

function unsignedRecord(
  record: AuditRecord,
  timestamp: string,
  previousHash: string,
): UnsignedAuditRecord {
  return {
    event: record.event,
    outcome: record.outcome,
    ...(record.clientId === undefined ? {} : { clientId: record.clientId }),
    ...(record.taskId === undefined ? {} : { taskId: record.taskId }),
    ...(record.leaseId === undefined ? {} : { leaseId: record.leaseId }),
    ...(record.origin === undefined ? {} : { origin: record.origin }),
    ...(record.method === undefined ? {} : { method: record.method }),
    ...(record.reasonCode === undefined ? {} : { reasonCode: record.reasonCode }),
    timestamp,
    previousHash,
  };
}

function unsignedRecordFromPersisted(record: PersistedAuditRecord): UnsignedAuditRecord {
  return unsignedRecord(record, record.timestamp, record.previousHash);
}

function unsignedManifest(manifest: AuditManifest): UnsignedAuditManifest {
  return {
    format: manifest.format,
    version: manifest.version,
    generation: manifest.generation,
    segments: manifest.segments,
  };
}

function manifestSegment(
  index: number,
  path: string,
  loaded: { records: PersistedAuditRecord[]; bytes: number; sha256: string },
): AuditManifestSegment {
  const first = loaded.records[0]!;
  const last = loaded.records.at(-1)!;
  return {
    index,
    file: basename(path),
    createdAt: first.timestamp,
    bytes: loaded.bytes,
    recordCount: loaded.records.length,
    firstHash: first.hash,
    lastHash: last.hash,
    sha256: loaded.sha256,
  };
}

function manifestSegmentsEqual(left: AuditManifestSegment, right: AuditManifestSegment): boolean {
  return (
    left.index === right.index &&
    left.file === right.file &&
    left.createdAt === right.createdAt &&
    left.bytes === right.bytes &&
    left.recordCount === right.recordCount &&
    hashesEqual(left.firstHash, right.firstHash) &&
    hashesEqual(left.lastHash, right.lastHash) &&
    hashesEqual(left.sha256, right.sha256)
  );
}

function sha256(contents: Buffer): string {
  return createHash("sha256").update(contents).digest("hex");
}

async function fileSha256(path: string): Promise<string> {
  const handle = await openPrivateFileIfPresent(path);
  if (handle === undefined) {
    throw new Error("Audit integrity verification failed: active segment disappeared.");
  }
  try {
    const metadata = await handle.stat();
    assertPrivateRegularFile(path, metadata);
    return sha256(await handle.readFile());
  } finally {
    await handle.close();
  }
}

function hashesEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function segmentExpired(createdAt: number, now: number): boolean {
  return now - createdAt >= RETENTION_MS;
}

function boundedByteLimit(name: string, value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 512 || value > maximum) {
    throw new Error(`The ${name} byte limit must be an integer from 512 to ${maximum}.`);
  }
  return value;
}

async function unlinkIfExists(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
