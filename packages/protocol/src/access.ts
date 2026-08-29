import { z } from "zod";

import {
  DataClassSchema,
  IdentifierSchema,
  OriginSchema,
  PROTOCOL_VERSION,
  ScopeSchema,
  SignatureSchema,
  TimestampSchema,
  scopeKey,
} from "./primitives.js";

const CapabilityClaimsBaseSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    capabilityId: IdentifierSchema,
    issuer: IdentifierSchema,
    clientId: IdentifierSchema,
    taskId: IdentifierSchema,
    browserProfileInstance: IdentifierSchema,
    tabId: IdentifierSchema,
    documentId: IdentifierSchema,
    topLevelOrigin: OriginSchema,
    scopes: z.array(ScopeSchema).min(1).max(32),
    dataClasses: z.array(DataClassSchema).max(6),
    egressDestinations: z.array(IdentifierSchema).max(16),
    issuedAt: TimestampSchema,
    expiresAt: TimestampSchema,
    idleTimeoutMs: z.number().int().positive().max(120_000),
    useLimit: z.number().int().positive().max(10_000),
    nonce: IdentifierSchema,
    audience: IdentifierSchema,
    policyVersion: IdentifierSchema,
    nonDelegable: z.literal(true),
  })
  .strict();

export const CapabilityClaimsSchema = CapabilityClaimsBaseSchema.superRefine((value, ctx) => {
  if (value.expiresAt <= value.issuedAt) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "must be after issuedAt" });
  }
  if (value.expiresAt - value.issuedAt > 600_000) {
    ctx.addIssue({
      code: "custom",
      path: ["expiresAt"],
      message: "capability TTL exceeds 10 minutes",
    });
  }
  const scopeKeys = value.scopes.map(scopeKey);
  if (new Set(scopeKeys).size !== scopeKeys.length) {
    ctx.addIssue({ code: "custom", path: ["scopes"], message: "duplicate scopes are not allowed" });
  }
});

export const CapabilitySchema = CapabilityClaimsBaseSchema.extend({
  signature: SignatureSchema,
}).superRefine((value, ctx) => {
  if (value.expiresAt <= value.issuedAt) {
    ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "must be after issuedAt" });
  }
  if (value.expiresAt - value.issuedAt > 600_000) {
    ctx.addIssue({
      code: "custom",
      path: ["expiresAt"],
      message: "capability TTL exceeds 10 minutes",
    });
  }
  const scopeKeys = value.scopes.map(scopeKey);
  if (new Set(scopeKeys).size !== scopeKeys.length) {
    ctx.addIssue({ code: "custom", path: ["scopes"], message: "duplicate scopes are not allowed" });
  }
});

export type CapabilityClaims = z.infer<typeof CapabilityClaimsSchema>;
export type Capability = z.infer<typeof CapabilitySchema>;

export const LeaseStateSchema = z.enum(["active", "revoked", "expired"]);

export const LeaseSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    leaseId: IdentifierSchema,
    capabilityId: IdentifierSchema,
    clientId: IdentifierSchema,
    taskId: IdentifierSchema,
    browserProfileInstance: IdentifierSchema,
    tabId: IdentifierSchema,
    documentId: IdentifierSchema,
    topLevelOrigin: OriginSchema,
    state: LeaseStateSchema,
    issuedAt: TimestampSchema,
    expiresAt: TimestampSchema,
    lastUsedAt: TimestampSchema,
    idleTimeoutMs: z.number().int().positive().max(120_000),
    remainingUses: z.number().int().nonnegative().max(10_000),
    revokedAt: TimestampSchema.optional(),
    revocationReason: z.string().min(1).max(256).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.expiresAt <= value.issuedAt) {
      ctx.addIssue({ code: "custom", path: ["expiresAt"], message: "must be after issuedAt" });
    }
    if (value.lastUsedAt < value.issuedAt || value.lastUsedAt > value.expiresAt) {
      ctx.addIssue({ code: "custom", path: ["lastUsedAt"], message: "outside lease lifetime" });
    }
    if (value.state === "revoked" && value.revokedAt === undefined) {
      ctx.addIssue({ code: "custom", path: ["revokedAt"], message: "required for revoked lease" });
    }
  });

export type Lease = z.infer<typeof LeaseSchema>;

export const AccessRequestSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    clientId: IdentifierSchema,
    taskId: IdentifierSchema,
    browserProfileInstance: IdentifierSchema,
    tabId: IdentifierSchema,
    documentId: IdentifierSchema,
    topLevelOrigin: OriginSchema,
    requestedScopes: z.array(ScopeSchema).min(1).max(32),
    requestedDataClasses: z.array(DataClassSchema).max(6),
    requestedEgressDestinations: z.array(IdentifierSchema).max(16),
    requestedTtlMs: z.number().int().positive().max(600_000),
    userGestureId: IdentifierSchema,
    userGestureAt: TimestampSchema,
  })
  .strict();

export type AccessRequest = z.infer<typeof AccessRequestSchema>;
