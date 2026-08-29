import { z } from "zod";

import {
  DigestSchema,
  IdentifierSchema,
  OriginSchema,
  TimestampSchema,
  UrlSchema,
} from "./primitives.js";

export const ElementReferenceSchema = z
  .object({
    referenceId: IdentifierSchema,
    tabId: IdentifierSchema,
    documentId: IdentifierSchema,
    topLevelOrigin: OriginSchema,
    domEpoch: z.number().int().nonnegative(),
    role: z.string().min(1).max(64),
    accessibleName: z.string().max(512),
    valueDigest: DigestSchema.optional(),
    issuedAt: TimestampSchema,
    expiresAt: TimestampSchema,
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 60_000) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "element references must have a lifetime of at most 60 seconds",
      });
    }
  });

export type ElementReference = z.infer<typeof ElementReferenceSchema>;

const ReadActionSchema = z
  .object({
    kind: z.literal("page.a11y.read"),
    maxNodes: z.number().int().positive().max(5_000).default(1_000),
  })
  .strict();

const ScreenshotActionSchema = z
  .object({
    kind: z.literal("page.screenshot.read"),
    viewportOnly: z.literal(true),
  })
  .strict();

const ScrollActionSchema = z
  .object({
    kind: z.literal("page.scroll"),
    deltaX: z.number().int().min(-10_000).max(10_000),
    deltaY: z.number().int().min(-10_000).max(10_000),
  })
  .strict();

const HighlightActionSchema = z
  .object({
    kind: z.literal("page.highlight"),
    target: ElementReferenceSchema,
  })
  .strict();

const ClickActionSchema = z
  .object({
    kind: z.literal("page.click.reversible"),
    target: ElementReferenceSchema,
    expectedEffect: z.literal("reversible-ui-only"),
  })
  .strict();

const FormFieldSchema = z
  .object({
    target: ElementReferenceSchema,
    fieldName: z.string().min(1).max(128),
    fieldType: z.enum(["text", "email", "search", "url", "tel", "number", "date"]),
    value: z.union([z.string().max(100_000), z.number().finite(), z.boolean()]),
    dataClass: z.enum(["public", "visible", "private", "sensitive"]),
  })
  .strict();

const FormDraftActionSchema = z
  .object({
    kind: z.literal("page.form.draft"),
    fields: z.array(FormFieldSchema).min(1).max(100),
  })
  .strict();

const NavigateActionSchema = z
  .object({
    kind: z.literal("page.navigate"),
    url: UrlSchema,
    target: z.literal("same-tab"),
  })
  .strict();

const FormSubmitActionSchema = z
  .object({
    kind: z.literal("page.form.submit"),
    target: ElementReferenceSchema,
    fieldsDigest: DigestSchema,
    account: z.string().min(1).max(256).optional(),
    destination: z.string().min(1).max(2048),
    summary: z.string().min(1).max(2_000),
    reversible: z.boolean(),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

const PublishActionSchema = z
  .object({
    kind: z.literal("content.publish"),
    destination: z.string().min(1).max(2048),
    contentDigest: DigestSchema,
    summary: z.string().min(1).max(2_000),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

const SendActionSchema = z
  .object({
    kind: z.literal("message.send"),
    destination: z.string().min(1).max(2048),
    recipients: z.array(z.string().min(1).max(512)).min(1).max(100),
    contentDigest: DigestSchema,
    summary: z.string().min(1).max(2_000),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

const DeleteActionSchema = z
  .object({
    kind: z.literal("data.delete"),
    resource: z.string().min(1).max(2048),
    count: z.number().int().positive().max(10_000),
    summary: z.string().min(1).max(2_000),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

const PermissionChangeActionSchema = z
  .object({
    kind: z.literal("security.permission.change"),
    principal: z.string().min(1).max(512),
    resource: z.string().min(1).max(2048),
    permissions: z.array(z.string().min(1).max(128)).min(1).max(100),
    summary: z.string().min(1).max(2_000),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

const FinancialTransactionActionSchema = z
  .object({
    kind: z.literal("financial.transaction"),
    payee: z.string().min(1).max(512),
    amountMinor: z.number().int().positive().safe(),
    currency: z.string().regex(/^[A-Z]{3}$/),
    summary: z.string().min(1).max(2_000),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

const OAuthConsentActionSchema = z
  .object({
    kind: z.literal("security.oauth.consent"),
    clientName: z.string().min(1).max(512),
    requestedPermissions: z.array(z.string().min(1).max(256)).min(1).max(100),
    summary: z.string().min(1).max(2_000),
    idempotencyKey: IdentifierSchema,
  })
  .strict();

export const ActionSchema = z.discriminatedUnion("kind", [
  ReadActionSchema,
  ScreenshotActionSchema,
  ScrollActionSchema,
  HighlightActionSchema,
  ClickActionSchema,
  FormDraftActionSchema,
  NavigateActionSchema,
  FormSubmitActionSchema,
  PublishActionSchema,
  SendActionSchema,
  DeleteActionSchema,
  PermissionChangeActionSchema,
  FinancialTransactionActionSchema,
  OAuthConsentActionSchema,
]);

export type Action = z.infer<typeof ActionSchema>;

export const ApprovalReceiptSchema = z
  .object({
    prepareId: IdentifierSchema,
    actionHash: DigestSchema,
    stateWitnessHash: DigestSchema,
    clientId: IdentifierSchema,
    taskId: IdentifierSchema,
    tabId: IdentifierSchema,
    documentId: IdentifierSchema,
    topLevelOrigin: OriginSchema,
    policyVersion: IdentifierSchema,
    issuedAt: TimestampSchema,
    expiresAt: TimestampSchema,
    consumedAt: TimestampSchema.optional(),
    userPresence: z
      .object({
        method: z.enum(["biometric", "security-key", "os-user-verification"]),
        verifiedAt: TimestampSchema,
      })
      .strict(),
    signature: z.string().min(16).max(4096),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 60_000) {
      ctx.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "approval TTL exceeds 60 seconds",
      });
    }
  });

export type ApprovalReceipt = z.infer<typeof ApprovalReceiptSchema>;
