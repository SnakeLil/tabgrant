import { z } from "zod";

export const PROTOCOL_VERSION = "0.1" as const;

export const IdentifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);

export const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const SignatureSchema = z.string().min(16).max(4096);
export const TimestampSchema = z.number().int().nonnegative().safe();

function isAllowedOrigin(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (parsed.origin !== value || parsed.username || parsed.password) return false;
    if (parsed.protocol === "https:") return true;
    return (
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" ||
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

export const OriginSchema = z
  .string()
  .max(2048)
  .refine(isAllowedOrigin, "expected a canonical HTTPS origin or loopback HTTP origin");

export const UrlSchema = z
  .string()
  .max(8192)
  .url()
  .refine((value) => {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  }, "only HTTP(S) URLs are supported");

export const DataClassSchema = z.enum([
  "public",
  "visible",
  "private",
  "sensitive",
  "secret",
  "authentication",
]);

export type DataClass = z.infer<typeof DataClassSchema>;

export const RiskLevelSchema = z.enum(["R0", "R1", "R2", "R3", "R4"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

const FixedScopeKindSchema = z.enum([
  "broker.status.read",
  "tab.metadata.read",
  "page.a11y.read",
  "page.element.inspect",
  "page.scroll",
  "page.highlight",
  "page.screenshot.read",
  "page.click.reversible",
  "page.form.draft",
  "page.navigate.same_origin",
]);

const FixedScopeSchema = z
  .object({
    kind: FixedScopeKindSchema,
  })
  .strict();

const AllowedOriginScopeSchema = z
  .object({
    kind: z.literal("page.navigate.allowed_origin"),
    origin: OriginSchema,
  })
  .strict();

const ModelEgressScopeSchema = z
  .object({
    kind: z.literal("data.egress.model"),
    providerId: IdentifierSchema,
    dataClasses: z
      .array(z.enum(["public", "visible", "private", "sensitive"]))
      .min(1)
      .max(4),
    maxBytes: z.number().int().positive().max(10_000_000),
  })
  .strict();

const ActionPrepareScopeSchema = z
  .object({
    kind: z.literal("action.prepare"),
    actionTypes: z.array(IdentifierSchema).min(1).max(32),
  })
  .strict();

export const ScopeSchema = z.discriminatedUnion("kind", [
  FixedScopeSchema,
  AllowedOriginScopeSchema,
  ModelEgressScopeSchema,
  ActionPrepareScopeSchema,
]);

export type Scope = z.infer<typeof ScopeSchema>;

export function scopeKey(scope: Scope): string {
  switch (scope.kind) {
    case "page.navigate.allowed_origin":
      return `${scope.kind}:${scope.origin}`;
    case "data.egress.model":
      return `${scope.kind}:${scope.providerId}:${[...scope.dataClasses].sort().join(",")}:${scope.maxBytes}`;
    case "action.prepare":
      return `${scope.kind}:${[...scope.actionTypes].sort().join(",")}`;
    default:
      return scope.kind;
  }
}
