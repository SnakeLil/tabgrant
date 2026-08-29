import { z } from "zod";

import { DigestSchema, RiskLevelSchema } from "./primitives.js";

export const BrokerErrorCodeSchema = z.enum([
  "INVALID_REQUEST",
  "UNSUPPORTED_PROTOCOL",
  "CAPABILITY_MISSING",
  "CAPABILITY_INVALID",
  "CAPABILITY_EXPIRED",
  "CAPABILITY_REVOKED",
  "CAPABILITY_SCOPE_DENIED",
  "CAPABILITY_CONTEXT_MISMATCH",
  "LEASE_EXPIRED",
  "LEASE_REVOKED",
  "STALE_ELEMENT_REFERENCE",
  "UNKNOWN_ACTION",
  "ACTION_FORBIDDEN",
  "SECRET_ACCESS_FORBIDDEN",
  "COOKIE_ACCESS_FORBIDDEN",
  "ARBITRARY_CODE_FORBIDDEN",
  "CDP_ACCESS_FORBIDDEN",
  "PREPARE_REQUIRED",
  "APPROVAL_REQUIRED",
  "APPROVAL_INVALID",
  "APPROVAL_EXPIRED",
  "APPROVAL_REPLAYED",
  "STATE_CHANGED",
  "RISK_NOT_SUPPORTED",
  "POLICY_UNAVAILABLE",
  "ENTERPRISE_POLICY_DENIED",
  "RATE_LIMITED",
  "INTERNAL_ERROR",
]);

export type BrokerErrorCode = z.infer<typeof BrokerErrorCodeSchema>;

export const PolicyRequirementSchema = z.enum([
  "TRUSTED_USER_PRESENCE",
  "ONE_TIME_RECEIPT",
  "STATE_WITNESS",
  "IDEMPOTENCY_KEY",
  "MANUAL_USER_COMPLETION",
]);

export const PolicyDecisionSchema = z
  .object({
    outcome: z.enum(["ALLOW", "ALLOW_PREPARE", "DENY"]),
    risk: RiskLevelSchema,
    actionKind: z.string().min(1).max(128),
    actionHash: DigestSchema.optional(),
    errorCode: BrokerErrorCodeSchema.optional(),
    reason: z.string().min(1).max(1_000),
    requirements: z.array(PolicyRequirementSchema).max(8),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.outcome === "DENY" && value.errorCode === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["errorCode"],
        message: "required for denied decisions",
      });
    }
    if (value.outcome !== "DENY" && value.errorCode !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["errorCode"],
        message: "only valid for denied decisions",
      });
    }
  });

export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

export const BrokerErrorSchema = z
  .object({
    code: BrokerErrorCodeSchema,
    message: z.string().min(1).max(1_000),
    retryable: z.boolean(),
  })
  .strict();

export type BrokerError = z.infer<typeof BrokerErrorSchema>;
