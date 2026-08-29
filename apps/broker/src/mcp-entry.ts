#!/usr/bin/env node
import { runMcpServer } from "./mcp.js";

const clientId = process.env.TABGRANT_CLIENT_ID;
const declaredModelProvider = process.env.TABGRANT_DECLARED_MODEL_PROVIDER;

if (clientId === undefined || declaredModelProvider === undefined) {
  process.stderr.write(
    "TabGrant requires TABGRANT_CLIENT_ID and TABGRANT_DECLARED_MODEL_PROVIDER. The provider is a user-visible client declaration, not a network-enforced destination.\n",
  );
  process.exitCode = 2;
} else {
  runMcpServer({
    clientId,
    declaredModelProvider,
    ...(process.env.TABGRANT_TASK_ID === undefined ? {} : { taskId: process.env.TABGRANT_TASK_ID }),
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`TabGrant MCP server failed: ${message}\n`);
    process.exitCode = 1;
  });
}
