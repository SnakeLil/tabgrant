export const TABGRANT_VERSION = "0.1.0";
export const WIRE_VERSION = 1 as const;
export const NATIVE_HOST_NAME = "io.tabgrant.bridge";
export const MAX_MESSAGE_BYTES = 1_048_576;
export const MAX_LEASE_TTL_MS = 10 * 60 * 1_000;
export const DEFAULT_LEASE_TTL_MS = 10 * 60 * 1_000;
export const LEASE_IDLE_TIMEOUT_MS = 2 * 60 * 1_000;
export const ACCESS_REQUEST_TTL_MS = 5 * 60 * 1_000;
export const LEASE_USE_LIMIT = 250;
export const LEASE_MAX_IN_FLIGHT = 2;
export const LEASE_COMMANDS_PER_WINDOW = 30;
export const LEASE_COMMAND_WINDOW_MS = 60 * 1_000;
export const LEASE_EGRESS_BUDGET_BYTES = 1_000_000;
export const SNAPSHOT_MAX_RESULT_BYTES = 256_000;
export const ACCESS_PENDING_PER_SESSION_LIMIT = 8;
export const ACCESS_PENDING_GLOBAL_LIMIT = 100;
export const ACCESS_REQUESTS_PER_SESSION_WINDOW = 20;
export const ACCESS_REQUESTS_GLOBAL_WINDOW = 120;
export const ACCESS_REQUEST_RATE_WINDOW_MS = 60 * 1_000;
export const ACCESS_REQUEST_RECORD_LIMIT = 512;
export const LEASE_RECORD_LIMIT = 200;
export const TERMINAL_RECORD_RETENTION_MS = 15 * 60 * 1_000;
export const STATE_MAINTENANCE_INTERVAL_MS = 30 * 1_000;

export const IMPLEMENTED_SCOPES = [
  "tab.metadata.read",
  "page.a11y.read",
  "page.element.inspect",
  "page.scroll",
  "page.highlight",
  "page.navigate.same_origin",
  "data.egress.model",
] as const;

export type ImplementedScope = (typeof IMPLEMENTED_SCOPES)[number];
