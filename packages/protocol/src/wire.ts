import { z } from "zod";

import { AccessRequestSchema, CapabilitySchema, LeaseSchema } from "./access.js";
import { ActionSchema, ApprovalReceiptSchema } from "./actions.js";
import { IdentifierSchema, PROTOCOL_VERSION } from "./primitives.js";
import { BrokerErrorSchema, PolicyDecisionSchema } from "./policy.js";

const StatusRequestSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    type: z.literal("broker.status.read"),
  })
  .strict();

const AccessWireRequestSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    type: z.literal("access.request"),
    access: AccessRequestSchema,
  })
  .strict();

const RevokeRequestSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    type: z.literal("lease.revoke"),
    leaseId: IdentifierSchema,
  })
  .strict();

const ActionRequestSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    type: z.literal("action.evaluate"),
    phase: z.enum(["prepare", "commit"]),
    action: ActionSchema,
    capability: CapabilitySchema,
    lease: LeaseSchema,
    stateWitnessHash: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
    approval: ApprovalReceiptSchema.optional(),
  })
  .strict();

export const BrokerRequestSchema = z
  .discriminatedUnion("type", [
    StatusRequestSchema,
    AccessWireRequestSchema,
    RevokeRequestSchema,
    ActionRequestSchema,
  ])
  .superRefine((value, ctx) => {
    if (value.type === "access.request" && value.requestId !== value.access.requestId) {
      ctx.addIssue({
        code: "custom",
        path: ["access", "requestId"],
        message: "nested access request ID must match the wire request ID",
      });
    }
  });

export type BrokerRequest = z.infer<typeof BrokerRequestSchema>;

const SuccessResponseSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    ok: z.literal(true),
    result: z.unknown(),
  })
  .strict();

const ErrorResponseSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    requestId: IdentifierSchema,
    ok: z.literal(false),
    error: BrokerErrorSchema,
  })
  .strict();

export const BrokerResponseSchema = z.discriminatedUnion("ok", [
  SuccessResponseSchema,
  ErrorResponseSchema,
]);

export type BrokerResponse = z.infer<typeof BrokerResponseSchema>;

const LeaseEventSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    eventId: IdentifierSchema,
    type: z.enum(["lease.updated", "lease.revoked"]),
    lease: LeaseSchema,
  })
  .strict();

const PolicyEventSchema = z
  .object({
    version: z.literal(PROTOCOL_VERSION),
    eventId: IdentifierSchema,
    type: z.literal("policy.decision"),
    decision: PolicyDecisionSchema,
  })
  .strict();

export const BrokerEventSchema = z.discriminatedUnion("type", [
  LeaseEventSchema,
  PolicyEventSchema,
]);
export type BrokerEvent = z.infer<typeof BrokerEventSchema>;

export const WireMessageSchema = z.union([
  BrokerRequestSchema,
  BrokerResponseSchema,
  BrokerEventSchema,
]);
export type WireMessage = z.infer<typeof WireMessageSchema>;
