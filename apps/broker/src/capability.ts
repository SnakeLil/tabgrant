import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import {
  CapabilityClaimsSchema,
  CapabilitySchema,
  type Capability,
  type CapabilityClaims,
  type Scope,
} from "@tabgrant/protocol";
import type { ImplementedScope } from "./constants.js";

export interface CapabilityGrant {
  readonly clientId: string;
  readonly taskId: string;
  readonly browserInstanceId: string;
  readonly tabId: number;
  readonly documentId: string;
  readonly origin: string;
  readonly scopes: ImplementedScope[];
  readonly declaredModelProvider?: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly useLimit: number;
}

export class CapabilityIssuer {
  public constructor(private readonly secret: Buffer) {}

  public issue(grant: CapabilityGrant): Capability {
    const claims = CapabilityClaimsSchema.parse({
      version: "0.1",
      capabilityId: randomUUID(),
      issuer: "tabgrant-broker",
      clientId: grant.clientId,
      taskId: grant.taskId,
      browserProfileInstance: grant.browserInstanceId,
      tabId: String(grant.tabId),
      documentId: grant.documentId,
      topLevelOrigin: grant.origin,
      scopes: grant.scopes.map((scope) => toProtocolScope(scope, grant.declaredModelProvider)),
      dataClasses: ["visible", "private"],
      egressDestinations:
        grant.declaredModelProvider === undefined ? [] : [grant.declaredModelProvider],
      issuedAt: grant.issuedAt,
      expiresAt: grant.expiresAt,
      idleTimeoutMs: 120_000,
      useLimit: grant.useLimit,
      nonce: randomUUID(),
      audience: grant.clientId,
      policyVersion: "v0.1",
      nonDelegable: true,
    });
    return CapabilitySchema.parse({ ...claims, signature: this.signClaims(claims) });
  }

  public verify(capability: Capability): boolean {
    const parsed = CapabilitySchema.safeParse(capability);
    if (!parsed.success) {
      return false;
    }
    const { signature, ...claims } = parsed.data;
    const expected = Buffer.from(this.signClaims(claims), "hex");
    const actual = Buffer.from(signature, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }

  private signClaims(claims: CapabilityClaims): string {
    return createHmac("sha256", this.secret).update(canonicalJson(claims)).digest("hex");
  }
}

function toProtocolScope(
  scope: ImplementedScope,
  declaredModelProvider: string | undefined,
): Scope {
  if (scope === "data.egress.model") {
    if (declaredModelProvider === undefined) {
      throw new Error("Model data release requires a declared provider label.");
    }
    return {
      kind: scope,
      providerId: declaredModelProvider,
      dataClasses: ["visible", "private"],
      maxBytes: 1_000_000,
    };
  }
  return { kind: scope };
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value.normalize("NFC"));
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key.normalize("NFC"))}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Capabilities must contain only canonical JSON values.");
}
