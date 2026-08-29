import { createHash } from "node:crypto";

import { ActionSchema, type Action } from "@tabgrant/protocol";

const ACTION_HASH_DOMAIN = "tabgrant/action/v0.1\n";

type CanonicalValue =
  null | boolean | number | string | CanonicalValue[] | { [key: string]: CanonicalValue };

function canonicalValue(value: unknown): CanonicalValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return typeof value === "string" ? value.normalize("NFC") : value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError("canonical values must contain finite numbers");
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (typeof value === "object") {
    const prototype = Reflect.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("canonical values must be plain objects");
    }
    const output: { [key: string]: CanonicalValue } = {};
    for (const key of Object.keys(value).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) throw new TypeError("canonical values must not contain undefined");
      output[key.normalize("NFC")] = canonicalValue(item);
    }
    return output;
  }
  throw new TypeError(`unsupported canonical value type: ${typeof value}`);
}

function normalizeAction(action: Action): Action {
  if (action.kind === "page.navigate") {
    return { ...action, url: new URL(action.url).href };
  }
  return action;
}

export function canonicalizeAction(input: unknown): string {
  const action = normalizeAction(ActionSchema.parse(input));
  return JSON.stringify(canonicalValue(action));
}

export function hashAction(input: unknown): string {
  return createHash("sha256")
    .update(ACTION_HASH_DOMAIN)
    .update(canonicalizeAction(input))
    .digest("hex");
}
